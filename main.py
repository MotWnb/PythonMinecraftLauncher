import asyncio
import hashlib
import json
import logging
import os
import platform
import queue
import re
import shutil
import sys
import zipfile
from logging import handlers
from pathlib import Path

import aiofiles
import aiofiles.os
import aiohttp


class Downloader:
    def __init__(self, retries=5, chunk_size=32768, timeout=30, session=None):
        self.retries = retries
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.session = session

    async def download(self, url: str, path: str, sha1: str = "") -> str | None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        if sha1 and Path(path).exists():
            h = hashlib.sha1()
            async with aiofiles.open(path, "rb") as f:
                while True:
                    chunk = await f.read(self.chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
            digest = h.hexdigest()
            if digest == sha1:
                logging.debug(f"文件已存在且校验通过，跳过下载：{path}")
                return path
            else:
                logging.warning(f"文件已存在但校验失败，将重新下载：{path}\n期望：{sha1}\n实际：{digest}")
                Path(path).unlink(missing_ok=True)

        for attempt in range(1, self.retries + 1):
            try:
                h = hashlib.sha1() if sha1 else None
                async with self.session.get(url=url, timeout=self.timeout) as resp:
                    if resp.status != 200:
                        if resp.status == 429:
                            logging.warning(f"{url}:429 请求频率过高")
                            raise ValueError()
                        logging.warning(f"服务器返回状态码 {resp.status}")
                        raise ValueError()

                    async with aiofiles.open(path, "wb") as f:
                        async for chunk in resp.content.iter_chunked(self.chunk_size):
                            await f.write(chunk)
                            if h:
                                h.update(chunk)

                if h:
                    digest = h.hexdigest()
                    if digest != sha1:
                        Path(path).unlink(missing_ok=True)
                        logging.warning(f"SHA1 校验失败：{path}\n期望：{sha1}\n实际：{digest}")
                        raise ValueError()
                return path

            except Exception as e:
                logging.warning(f"【第 {attempt}/{self.retries} 次尝试】下载失败：{url}\n原因：{str(e)}")
                if attempt == self.retries:
                    logging.warning(f"下载最终失败：{url}")
                    raise
                await asyncio.sleep(1)
        return None


async def download_version_manifest_v2(dl: Downloader):
    logging.info("开始下载版本清单文件")
    url = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
    await dl.download(url, version_manifest_v2_path)


async def get_version_dict_list():
    async with aiofiles.open(version_manifest_v2_path, mode="r") as f:
        version_manifest_v2_str = await f.read()
        version_manifest_v2_dict = json.loads(version_manifest_v2_str)
        version_manifest_v2_latest_versions = version_manifest_v2_dict["latest"]
        version_manifest_v2_versions = version_manifest_v2_dict["versions"]
        return version_manifest_v2_latest_versions, version_manifest_v2_versions


async def get_remote_version_list(version_dict_list):
    logging.info("开始统计版本")
    release_version_list = []
    snapshot_version_list = []
    version_list = []
    for version in version_dict_list:
        if version["type"] == "snapshot":
            snapshot_version_list.append(version["id"])
        elif version["type"] == "release":
            release_version_list.append(version["id"])
        version_list.append(version["id"])
    return snapshot_version_list, release_version_list, version_list


async def get_selected_version(version_list, version_dict_list):
    selected_version_str = input("请输入目标版本" + str(version_list))
    if selected_version_str in version_list:
        for version in version_dict_list:
            if version["id"] == selected_version_str:
                return version
    logging.warning(f"输入的版本号无效：{selected_version_str}")
    raise ValueError()


async def download_assets_of_selected_version(dl: Downloader, selected_version_json):
    asset_root_url = "https://resources.download.minecraft.net"
    assets_folder = os.path.join(minecraft_folder, "assets")
    asset_index_dict = selected_version_json["assetIndex"]
    asset_index_id = asset_index_dict["id"]
    asset_index_sha1 = asset_index_dict["sha1"]
    asset_index_url = asset_index_dict["url"]
    asset_index_path = os.path.join(assets_folder, "indexes", f"{asset_index_id}.json")
    asset_objects_folder = os.path.join(assets_folder, "objects")
    await dl.download(asset_index_url, asset_index_path, asset_index_sha1)
    async with aiofiles.open(asset_index_path, "r") as f:
        asset_index = json.loads(await f.read())
        asset_index_objects = asset_index["objects"]

        semaphore = asyncio.Semaphore(256)

        async def bounded_download(url, path, sha1):
            async with semaphore:
                return await dl.download(url, path, sha1)

        tasks = []
        for asset_index_object_path in asset_index_objects:
            asset_index_object_hash = asset_index_objects[asset_index_object_path]["hash"]
            asset_index_object_url = f"{asset_root_url}/{asset_index_object_hash[:2]}/{asset_index_object_hash}"
            asset_index_object_path = os.path.join(asset_objects_folder, asset_index_object_hash[:2],
                                                   asset_index_object_hash)
            tasks.append(bounded_download(asset_index_object_url, asset_index_object_path, asset_index_object_hash))
        await asyncio.gather(*tasks)


async def download_selected_version_client_jar(dl: Downloader, selected_version_json, selected_version_folder,
                                               selected_version_id):
    selected_version_client_jar_dict = selected_version_json["downloads"]["client"]
    selected_version_client_jar_url = selected_version_client_jar_dict["url"]
    selected_version_client_jar_path = os.path.join(selected_version_folder, f"{selected_version_id}.jar")
    selected_version_client_jar_sha1 = selected_version_client_jar_dict["sha1"]
    await dl.download(selected_version_client_jar_url, selected_version_client_jar_path,
                      selected_version_client_jar_sha1)


def is_allowed(rules, features: dict = None):
    action = False
    for rule in rules:
        if "os" in rule:
            os_rule = rule["os"]
            if "name" in os_rule:
                if name != os_rule["name"]:
                    continue
            if "arch" in os_rule:
                if arch != os_rule["arch"]:
                    continue
            if "version" in os_rule:
                version_pattern = re.compile(os_rule["version"])
                if not version_pattern.match(os_version):
                    continue
            if "feature" in os_rule:
                if features is not None:
                    target_features: dict = os_rule["feature"]
                    for target_feature in target_features:
                        if target_feature in features:
                            if features[target_feature] != target_features[target_feature]:
                                continue
                        else:
                            continue
                else:
                    continue
        if rule["action"] == "allow":
            action = True
        if rule["action"] == "disallow":
            action = False
    return action


async def download_library(dl: Downloader, library_dict, selected_version_folder, selected_version_id,
                           libraries_folder):
    if "rules" in library_dict:
        rules = library_dict["rules"]
        if not is_allowed(rules):
            return
    if "classifiers" in library_dict["downloads"]:
        artifact_dict = library_dict["downloads"]["classifiers"][library_dict["natives"][name]]
    else:
        artifact_dict = library_dict["downloads"]["artifact"]
    artifact_url = artifact_dict["url"]
    artifact_path = str(os.path.join(libraries_folder, artifact_dict["path"]))
    artifact_sha1 = artifact_dict["sha1"]
    await dl.download(artifact_url, artifact_path, artifact_sha1)
    if "classifiers" in library_dict["downloads"]:
        # 解压目标文件夹
        natives_folder = os.path.join(selected_version_folder, f"{selected_version_id}-natives")
        os.makedirs(natives_folder, exist_ok=True)

        # 获取需要排除的路径前缀
        exclude_prefixes = library_dict.get("extract", {}).get("exclude", [])

        loop = asyncio.get_running_loop()

        def unzip_sync():
            with zipfile.ZipFile(artifact_path, "r") as zf:
                for member in zf.namelist():
                    # 排除 exclude
                    if any(member.startswith(p) for p in exclude_prefixes):
                        continue
                    # 只提取文件，不保留目录结构
                    if member.endswith("/"):
                        continue
                    data = zf.read(member)
                    # 文件名去掉路径，只保留最后部分
                    filename = os.path.basename(member)
                    target_path = os.path.join(natives_folder, filename)
                    logging.debug(f"正在解压{filename}从{artifact_path}")
                    with open(target_path, "wb") as f:
                        f.write(data)

        # 放到线程池执行，避免阻塞事件循环
        await loop.run_in_executor(None, unzip_sync)  # noinspection PyTypeChecker
        # 奇妙警告,爱来自PY-63820,不知道为何还无法抑制


async def download_selected_version_libraries(dl: Downloader, selected_version_json,
                                              selected_version_folder, selected_version_id):
    libraries_folder = os.path.join(minecraft_folder, "libraries")
    selected_version_libraries_list = selected_version_json["libraries"]
    tasks = []
    for library in selected_version_libraries_list:
        tasks.append(download_library(dl, library, selected_version_folder, selected_version_id, libraries_folder))
    await asyncio.gather(*tasks)


async def download_selected_version(dl: Downloader, selected_version):
    selected_version_id = selected_version["id"]

    selected_version_folder = os.path.join(versions_folder, selected_version_id)
    selected_version_json_path = os.path.join(selected_version_folder, f"{selected_version_id}.json")
    selected_version_json_url = selected_version["url"]
    selected_version_json_sha1 = selected_version["sha1"]
    await dl.download(selected_version_json_url, selected_version_json_path, selected_version_json_sha1)
    async with aiofiles.open(selected_version_json_path, mode="r") as f:
        selected_version_json = json.loads(await f.read())
        tasks = [download_assets_of_selected_version(dl, selected_version_json),
                 download_selected_version_client_jar(dl, selected_version_json, selected_version_folder,
                                                      selected_version_id),
                 download_selected_version_libraries(dl, selected_version_json,
                                                     selected_version_folder, selected_version_id)
                 ]
        await asyncio.gather(*tasks)


async def download_main(dl: Downloader):
    await download_version_manifest_v2(dl)
    latest_version_dict, version_dict_list = await get_version_dict_list()
    snapshot_version_list, release_version_list, version_list = await get_remote_version_list(version_dict_list)
    selected_version = await get_selected_version(release_version_list, version_dict_list)
    await download_selected_version(dl, selected_version)


async def get_local_version_list():  # and dict(
    logging.debug("开始统计版本")
    subfolder_names = []
    subfolder_dict = {}
    if not aiofiles.os.path.exists(versions_folder):
        logging.warning(f"versions目录不存在:{versions_folder}")
        raise Exception
    for item_name in await aiofiles.os.listdir(versions_folder):
        item_full_path = os.path.join(versions_folder, item_name)
        if os.path.isdir(item_full_path):  # 判断是否为目录
            jar_full_path = os.path.join(item_full_path, f"{item_name}.jar")
            json_full_path = os.path.join(item_full_path, f"{item_name}.json")
            if await aiofiles.os.path.exists(jar_full_path) and await aiofiles.os.path.exists(json_full_path):
                subfolder_names.append(item_name)
                subfolder_dict[item_name] = item_full_path
    # 我感觉应该不会有人随便往versions里面扔文件夹吧。。。

    return subfolder_names, subfolder_dict


async def get_local_selected_version(local_version_list, local_version_dict) -> str | None:
    selected_version_str = input(f"请输入想要启动的版本{local_version_list}")
    if selected_version_str in local_version_list:
        selected_version_folder = local_version_dict[selected_version_str]
        selected_version_json_path = os.path.join(selected_version_folder, f"{selected_version_str}.json")
        async with aiofiles.open(selected_version_json_path, "r") as f:
            selected_version_json_str = await f.read()
            selected_version_json = json.loads(selected_version_json_str)
            return selected_version_json
    logging.warning(f"输入的版本号无效{selected_version_str}")
    raise ValueError


async def get_launch_arguments(selected_version_json):
    if "arguments" in selected_version_json:
        game_argument_list = []
        jvm_argument_list = []
        arguments = selected_version_json["arguments"]
        game_arguments: list = arguments["game"]
        jvm_arguments: list = arguments["jvm"]
        game_arguments_str = ""
        jvm_arguments_str = ""
        for argument in game_arguments:
            if type(argument) == dict:
                rules = argument["rules"]
                if is_allowed(
                        rules
                        # TODO: features
                ):
                    value = argument["value"]
                    if type(value) == str:
                        game_argument_list.append(value)
                    elif type(value) == list:
                        for v in value:
                            game_argument_list.append(v)

            elif type(argument) == str:
                jvm_argument_list.append(argument)
        for argument in jvm_arguments:
            if type(argument) == dict:
                rules = argument["rules"]
                if is_allowed(
                        rules
                        # TODO: features
                ):
                    value = argument["value"]
                    if type(value) == str:
                        jvm_argument_list.append(value)
                    elif type(value) == list:
                        for v in value:
                            jvm_argument_list.append(v)

            elif type(argument) == str:
                jvm_argument_list.append(argument)
        for game_argument in game_argument_list:
            game_arguments_str = game_arguments_str + game_argument + " "
        for jvm_argument in jvm_argument_list:
            jvm_arguments_str = jvm_arguments_str + jvm_argument + " "
        main_class = selected_version_json["mainClass"]
        argument_str = (jvm_arguments_str + main_class + game_arguments_str).strip()
        print(argument_str)


async def launch_selected_version(dl: Downloader, selected_version_json):
    await get_launch_arguments(selected_version_json)


async def launch_main(dl: Downloader):
    local_version_list, local_version_dict = await get_local_version_list()
    selected_version_json = await get_local_selected_version(local_version_list, local_version_dict)
    await launch_selected_version(dl, selected_version_json)


async def main():
    connector = aiohttp.TCPConnector(limit=512)
    async with aiohttp.ClientSession(connector=connector) as session:
        dl = Downloader(session=session)
        # await launch_main(dl)
        await download_main(dl)


def get_architecture():
    arch_ = platform.machine().lower()  # 统一转为小写，避免大小写问题 (虽然我也不知道这些架构能不能跑起来)
    if arch_ in ['x86_64', 'amd64']:
        return 'x64'
    elif arch_ in ['i386', 'i686', 'x86']:
        return 'x86'
    elif arch_ in ['aarch64', 'arm64']:
        return 'arm64'
    else:
        return f"未知架构: {arch_}"


def get_os():
    os_name = platform.system()
    if os_name == 'Windows':
        return 'windows'
    elif os_name == 'linux':
        return 'Linux'
    elif os_name == 'Darwin':
        return 'osx'
    else:
        return f"未知操作系统: {os_name}"


def get_os_version():
    if name == "windows":
        return platform.release() + "." + platform.version().split('.')[2]
    elif name == "osx":
        return platform.mac_ver()[0]
    elif name == "linux":
        return platform.release()
    else:
        return ""  # 未知系统返回空


def rotate_logs(base_log_file: str, max_files: int = 5):
    for i in range(max_files - 1, 0, -1):
        src = f"{base_log_file}.{i}"
        dst = f"{base_log_file}.{i + 1}"
        if os.path.exists(src):
            shutil.move(src, dst)
    if os.path.exists(base_log_file):
        shutil.move(base_log_file, f"{base_log_file}.1")


class InfoFilter(logging.Filter):
    def filter(self, record):
        # 只允许 INFO 以上
        return record.levelno >= logging.INFO


def setup_async_logger(log_file: str):
    rotate_logs(log_file, max_files=5)

    log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_queue)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(queue_handler)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    ))
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    console_handler.addFilter(InfoFilter())

    queue_listener = logging.handlers.QueueListener(
        log_queue, file_handler, console_handler
    )
    queue_listener.start()

    logging.getLogger("asyncio").setLevel(logging.WARNING)

    return queue_listener


if __name__ == "__main__":
    cwd = os.getcwd()
    pml_folder = os.path.join(cwd, "PML")
    os.makedirs(pml_folder, exist_ok=True)
    minecraft_folder = os.path.join(cwd, ".minecraft")
    name = get_os()
    arch = get_architecture()
    os_version = get_os_version()
    version_manifest_v2_path = os.path.join(pml_folder, "version_manifest_v2.json")
    versions_folder = os.path.join(minecraft_folder, "versions")

    logfile_path = os.path.join(pml_folder, "log.log")
    listener = setup_async_logger(logfile_path)

    asyncio.run(main())
