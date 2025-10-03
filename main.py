import asyncio
import hashlib
import json
import os
from pathlib import Path

import aiofiles
import aiohttp


class Downloader:
    def __init__(self, retries=3, chunk_size=8192, timeout=30, session=None):
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
                print(f"文件已存在且校验通过，跳过下载：{path}")
                return path
            else:
                print(f"文件已存在但校验失败，将重新下载：{path}\n期望：{sha1}\n实际：{digest}")
                Path(path).unlink(missing_ok=True)

        for attempt in range(1, self.retries + 1):
            try:
                h = hashlib.sha1() if sha1 else None
                async with self.session.get(url=url, timeout=self.timeout) as resp:
                    if resp.status != 200:
                        if resp.status == 429:
                            raise ValueError(f"请求频率过高")
                        raise ValueError(f"服务器返回状态码 {resp.status}")

                    async with aiofiles.open(path, "wb") as f:
                        async for chunk in resp.content.iter_chunked(self.chunk_size):
                            await f.write(chunk)
                            if h:
                                h.update(chunk)

                if h:
                    digest = h.hexdigest()
                    if digest != sha1:
                        Path(path).unlink(missing_ok=True)
                        raise ValueError(f"SHA1 校验失败：{path}\n期望：{sha1}\n实际：{digest}")
                return path

            except Exception as e:
                print(f"【第 {attempt}/{self.retries} 次尝试】下载失败：{url}\n原因：{str(e)}")
                if attempt == self.retries:
                    print(f"下载最终失败：{url}")
                    raise
                await asyncio.sleep(1)
        return None


async def download_version_manifest_v2(dl: Downloader, version_manifest_v2_path):
    url = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
    await dl.download(url, version_manifest_v2_path)


async def get_version_dict_list(version_manifest_v2_path):
    async with aiofiles.open(version_manifest_v2_path, mode="r") as f:
        version_manifest_v2_str = await f.read()
        version_manifest_v2_dict = json.loads(version_manifest_v2_str)
        version_manifest_v2_latest_versions = version_manifest_v2_dict["latest"]
        version_manifest_v2_versions = version_manifest_v2_dict["versions"]
        return version_manifest_v2_latest_versions, version_manifest_v2_versions


async def get_version_list(version_dict_list):
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
    raise ValueError(f"输入的版本号无效：{selected_version_str}")


async def download_assets_of_selected_version(dl: Downloader, selected_version_json, minecraft_folder):
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


async def download_selected_version(dl: Downloader, selected_version, minecraft_folder, version_isolation=False):
    minecraft_versions_path = os.path.join(minecraft_folder, "versions")
    selected_version_id = selected_version["id"]

    selected_version_folder = os.path.join(minecraft_versions_path, selected_version_id)
    selected_version_json_path = os.path.join(selected_version_folder, f"{selected_version_id}.json")
    selected_version_json_url = selected_version["url"]
    selected_version_json_sha1 = selected_version["sha1"]
    await dl.download(selected_version_json_url, selected_version_json_path, selected_version_json_sha1)
    async with aiofiles.open(selected_version_json_path, mode="r") as f:
        selected_version_json = json.loads(await f.read())
        await download_assets_of_selected_version(dl, selected_version_json, minecraft_folder)


async def main():
    async with aiohttp.ClientSession() as session:
        cwd = os.getcwd()
        pml_folder = os.path.join(cwd, "PML")
        minecraft_folder = os.path.join(cwd, ".minecraft")
        version_isolation = False
        version_manifest_v2_path = os.path.join(pml_folder, "version_manifest_v2.json")

        dl = Downloader(session=session)
        print("开始下载版本清单文件")
        await download_version_manifest_v2(dl, version_manifest_v2_path)
        print("开始统计版本")
        latest_version_dict, version_dict_list = await get_version_dict_list(version_manifest_v2_path)
        snapshot_version_list, release_version_list, version_list = await get_version_list(version_dict_list)
        selected_version = await get_selected_version(release_version_list, version_dict_list)
        await download_selected_version(dl, selected_version, minecraft_folder, version_isolation)


if __name__ == "__main__":
    asyncio.run(main())
