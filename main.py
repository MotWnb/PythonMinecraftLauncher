import asyncio
import hashlib
import json
import os
from pathlib import Path

import aiohttp
import aiofiles


class Downloader:
    def __init__(self, retries=3, chunk_size=8192, timeout=30, session=None):
        self.retries = retries
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.session = session

    async def download(self, url: str, path: str, sha1: str = "") -> str | None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        for attempt in range(1, self.retries + 1):
            try:
                h = hashlib.sha1() if sha1 else None
                async with self.session.get(url=url, timeout=self.timeout) as resp:
                    if resp.status != 200:
                        raise ValueError(f"服务器返回状态码 {resp.status}")

                    with open(path, "wb") as f:
                        async for chunk in resp.content.iter_chunked(self.chunk_size):
                            f.write(chunk)
                            if h:
                                h.update(chunk)

                if h:
                    digest = h.hexdigest()
                    if digest != sha1:
                        Path(path).unlink(missing_ok=True)
                        raise ValueError(
                            f"SHA1 校验失败：{path}\n期望：{sha1}\n实际：{digest}"
                        )

                print(f"下载完成：{path}")
                return path

            except Exception as e:
                print(f"【第 {attempt}/{self.retries} 次尝试】下载失败：{url}\n原因：{e}")
                if attempt == self.retries:
                    print(f"下载最终失败：{url}")
                    raise
                await asyncio.sleep(1)  # 简单退避，避免持续请求服务器
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

async def download_assets_of_selected_version(selected_version_json, minecraft_folder):
    assets_folder = os.path.join(minecraft_folder, "assets")

async def download_selected_version(dl: Downloader, selected_version, minecraft_folder, version_isolation=False):
    minecraft_versions_path = os.path.join(minecraft_folder, "versions")
    selected_version_id = selected_version["id"]

    selected_version_folder = os.path.join(minecraft_versions_path, selected_version_id)
    selected_version_json_path = os.path.join(selected_version_folder, f"{selected_version_id}.json")
    selected_version_json_url = selected_version["url"]
    selected_version_json_sha1 = selected_version["sha1"]
    await dl.download(selected_version_json_url, selected_version_json_path, selected_version_json_sha1)
    async with aiofiles.open(selected_version_json_path, mode="r") as f:
        selected_version_json = await f.read()



async def main():
    async with aiohttp.ClientSession() as session:
        cwd = os.getcwd()
        pml_folder = os.path.join(cwd, "PML")
        minecraft_folder = os.path.join(cwd, ".minecraft")
        version_isolation = False
        version_manifest_v2_path = os.path.join(pml_folder, "version_manifest_v2.json")

        dl = Downloader(session=session)

        await download_version_manifest_v2(dl, version_manifest_v2_path)
        latest_version_dict, version_dict_list = await get_version_dict_list(version_manifest_v2_path)
        snapshot_version_list, release_version_list, version_list = await get_version_list(version_dict_list)
        selected_version = await get_selected_version(release_version_list, version_dict_list)
        await download_selected_version(dl, selected_version, minecraft_folder, version_isolation)


if __name__ == "__main__":
    asyncio.run(main())
