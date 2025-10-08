import asyncio
import hashlib
import json
import logging
import uuid
import webbrowser
from typing import List, Optional

import keyring
import msal
import pyperclip
from aiohttp import ClientSession


class AccountManager:
    # MSA相关配置
    _MSA_AUTHORITY = "https://login.microsoftonline.com/consumers"
    _MSA_CLIENT_ID = "de243363-2e6a-44dc-82cb-ea8d6b5cd98d"
    _MSA_REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
    _MSA_SCOPE = [
        "XboxLive.signin",
        "XboxLive.offline_access"
    ]
    _XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
    _XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
    _MC_AUTH_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
    _MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"

    def __init__(self, session: Optional[ClientSession] = None):
        self.logger = logging.getLogger(__name__)
        self.service_name = "PML"
        self.account_list = self.get_account_list()
        self.session = session
        self._is_internal_session = session is None
        # 初始化MSAL客户端
        self.msal_app = msal.PublicClientApplication(
            self._MSA_CLIENT_ID,
            authority=self._MSA_AUTHORITY
        )

    async def _ensure_session(self):
        """确保session已初始化（内部使用，首次调用网络方法时自动创建）"""
        if self.session is None or self.session.closed:
            self.session = ClientSession()
            self._is_internal_session = True

    def get_account_list(self) -> List[str]:  # 获取账户列表(元数据)
        metadata_str = keyring.get_password(self.service_name, "metadata")
        if not metadata_str:
            return []  # 首次使用，返回空列表
        try:
            return json.loads(metadata_str)
        except json.JSONDecodeError:
            self.logger.warning(f"元数据损坏，重置元数据{metadata_str}")
            keyring.delete_password(self.service_name, "metadata")
            # 元数据损坏时重置
            return []

    def save_account_list(self, metadata: List[str]):  # 保存账户列表(元数据)
        keyring.set_password(self.service_name, "metadata", json.dumps(metadata))

    def get_account(self, user_name: str) -> dict:  # 获取账户信息
        account = keyring.get_password(self.service_name, user_name)
        if account:
            return json.loads(account)
        logging.warning(f"未找到账户: {user_name}")
        raise KeyError()

    def save_online_account(self, user_name: str, user_uuid: str, refresh_token: str):
        account = {
            "user_uuid": user_uuid,
            "refresh_token": refresh_token,
            "account_type": "msa"
        }
        keyring.set_password(self.service_name, user_name, json.dumps(account))
        if user_name not in self.account_list:
            self.account_list.append(user_name)
            self.save_account_list(self.account_list)
        self.logger.info(f"保存账户: {user_name}, 新账户列表{self.account_list}")

    @staticmethod
    def offline_player_uuid(username: str) -> uuid.UUID:  # 或许和HMCL等价? 没试过(
        name_bytes = ("OfflinePlayer:" + username).encode("utf-8")
        md5 = hashlib.md5(name_bytes).digest()
        b = bytearray(md5)
        b[6] = (b[6] & 0x0F) | (3 << 4)  # version = 3
        b[8] = (b[8] & 0x3F) | 0x80  # variant = RFC 4122
        return uuid.UUID(bytes=bytes(b))

    def save_offline_account(self, user_name: str, access_token: str = None):
        if not access_token:
            random_uuid = uuid.uuid4()
            access_token = random_uuid.hex  # hex属性直接返回不带连字符的32位字符串
        user_uuid = self.offline_player_uuid(user_name)
        account = {
            "user_uuid": user_uuid,
            "access_token": access_token,
            "account_type": "offline"
        }
        keyring.set_password(self.service_name, user_name, json.dumps(account))
        if user_name not in self.account_list:
            self.account_list.append(user_name)
            self.save_account_list(self.account_list)
        self.logger.info(f"保存账户: {user_name}, 新账户列表{self.account_list}")

    def delete_account(self, user_name: str):
        keyring.delete_password(self.service_name, user_name)
        self.account_list.remove(user_name)
        self.save_account_list(self.account_list)
        self.logger.info(f"删除账户: {user_name}, 新账户列表{self.account_list}")

    def update_online_account(self, user_uuid: str, username: str, refresh_token: str, old_username: str = None):
        if old_username:
            self.delete_account(old_username)
        self.save_online_account(username, user_uuid, refresh_token)
        self.logger.info(f"更新账户: {username}, 新账户列表{self.account_list}")

    def update_offline_account(self, user_name: str, old_username: str):
        self.delete_account(old_username)
        self.save_offline_account(user_name, self.offline_player_uuid(user_name).hex)
        self.logger.info(f"更新账户: {user_name}, 新账户列表{self.account_list}")

    def get_account_type(self, user_name: str) -> str:
        return self.get_account(user_name)["account_type"]
        # return "msa" or "offline"

    def get_user_uuid(self, user_name: str) -> str:
        return self.get_account(user_name)["user_uuid"]

    def get_offline_account_access_token(self, user_name: str) -> str:
        return self.get_account(user_name)["access_token"]

    def get_refresh_token(self, user_name: str) -> str:
        return self.get_account(user_name)["refresh_token"]

    def get_username_list(self) -> List[str]:  # 获取账户列表(用户名)
        return self.account_list

    async def msa_login(self) -> tuple:
        """执行MSA登录流程，返回(username, uuid, refresh_token)"""
        await self._ensure_session()
        # 1. 获取设备代码（原有逻辑不变）
        device_flow = self.msal_app.initiate_device_flow(scopes=self._MSA_SCOPE)
        if "error" in device_flow:
            raise Exception(f"设备流错误: {device_flow['error_description']}")

        # 2. 显示登录信息并打开浏览器（原有逻辑不变）
        print(f"请在浏览器中打开: {device_flow['verification_uri']}")
        print(f"输入代码: {device_flow['user_code']}")
        pyperclip.copy(device_flow['user_code'])
        webbrowser.open(device_flow['verification_uri'])

        # 3. 轮询等待用户完成登录（原有逻辑不变，建议sleep改为3秒避免频繁请求）
        auth_result = None
        while not auth_result:
            auth_result = self.msal_app.acquire_token_by_device_flow(device_flow)
            if "access_token" in auth_result:
                break
            await asyncio.sleep(3)  # 原1秒→3秒，减少接口压力
        print(f"auth_result{auth_result}")

        # 4. 获取XBL令牌（原有逻辑不变）
        xbl_token = await self._get_xbl_token(auth_result['access_token'])
        print(f"xbl_token:{xbl_token}")
        # 5. 获取XSTS令牌（原有逻辑不变）
        xsts_token, user_hash = await self._get_xsts_token(xbl_token)
        print(f"xsts_token:{xsts_token}, user_hash:{user_hash}")
        # 6. 获取Minecraft访问令牌（仅拿access_token，后续用它请求个人资料）
        mc_auth = await self._get_minecraft_auth(xsts_token, user_hash)
        print(f"mc_auth:{mc_auth}")

        # 用mc_auth的access_token调用profile接口，拿到正确的“显示名”和“UUID”
        mc_profile = await self._get_minecraft_profile(mc_auth['access_token'])
        print(f"mc_profile:{mc_profile}")

        return (
            mc_profile['name'],
            mc_profile['id'],
            auth_result['refresh_token']
        )

    async def refresh_access_token(self, username: str) -> tuple:
        """
        使用refresh token刷新获取新的access token，同时处理用户名变更

        返回: (新的access_token, 最新用户名, 用户UUID)
        """
        await self._ensure_session()
        # 1. 获取本地存储的账户信息（含UUID和旧refresh token）
        account_info = self.get_account(username)
        stored_uuid = account_info['user_uuid']  # 本地存储的UUID（作为账户唯一标识）
        refresh_token = account_info['refresh_token']

        # 2. 使用MSAL刷新令牌
        result = self.msal_app.acquire_token_by_refresh_token(
            refresh_token,
            scopes=self._MSA_SCOPE
        )

        if "error" in result:
            raise Exception(f"令牌刷新失败: {result['error_description']}")

        # 3. 若返回新的refresh token，先暂存（后续可能随用户名更新一起保存）
        new_refresh_token = result.get('refresh_token', refresh_token)

        # 4. 流程：XBL → XSTS → Minecraft认证 → 获取最新个人资料（含可能变更的用户名）
        xbl_token = await self._get_xbl_token(result['access_token'])
        xsts_token, user_hash = await self._get_xsts_token(xbl_token)
        mc_auth = await self._get_minecraft_auth(xsts_token, user_hash)
        # 关键：获取最新的用户名和UUID（验证UUID是否一致，确保是同一个账户）
        mc_profile = await self._get_minecraft_profile(mc_auth['access_token'])
        latest_username = mc_profile['name']  # 可能已变更的最新用户名
        latest_uuid = mc_profile['id']  # 不变的UUID（用于校验）

        # 5. 校验UUID一致性（防止刷新时账户混淆）
        if latest_uuid != stored_uuid:
            raise Exception(f"账户UUID不匹配！本地存储: {stored_uuid}，远程获取: {latest_uuid}")

        # 6. 若用户名已变更，更新本地存储的用户名（保持UUID和新refresh token）
        if latest_username != username:
            self.update_online_account(
                user_uuid=latest_uuid,
                username=latest_username,
                refresh_token=new_refresh_token,
                old_username=username  # 删除旧用户名的记录
            )
            self.logger.info(f"用户名已更新: {username} → {latest_username}")

        # 7. 若用户名未变更，但有新的refresh token，仅更新refresh token
        elif new_refresh_token != refresh_token:
            self.save_online_account(
                user_name=username,
                user_uuid=stored_uuid,
                refresh_token=new_refresh_token
            )

        # 返回：新的access token、最新用户名、UUID
        return mc_auth['access_token'], latest_username, latest_uuid

    async def refresh_account_token(self, username: str):
        """刷新令牌入口，处理用户名变更并反馈结果"""
        try:
            # 调用刷新方法，获取新令牌和可能的新用户名
            access_token, latest_username, user_uuid = await self.refresh_access_token(username)

            # 反馈结果（区分是否更新了用户名）
            if latest_username != username:
                print(f"刷新成功！用户名已更新为: {latest_username}，新令牌: {access_token[:10]}...")
            else:
                print(f"刷新成功，新令牌: {access_token[:10]}...")
        except Exception as e:
            print(f"刷新失败: {str(e)}")

    async def _get_xbl_token(self, access_token: str) -> str:
        """获取Xbox Live令牌"""
        payload = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"d={access_token}"
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }

        async with self.session.post(self._XBL_AUTH_URL, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"XBL认证失败: {await resp.text()}")

            data = await resp.json()
            return data['Token']

    async def _get_xsts_token(self, xbl_token: str) -> tuple:
        """获取XSTS令牌和用户哈希"""
        payload = {
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [xbl_token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }

        async with self.session.post(self._XSTS_AUTH_URL, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"XSTS认证失败: {await resp.text()}")

            data = await resp.json()
            return data['Token'], data['DisplayClaims']['xui'][0]['uhs']

    async def _get_minecraft_profile(self, mc_access_token: str) -> dict:
        """调用Minecraft个人资料接口，获取规范的用户名（name）和UUID（id）"""
        # 请求必须携带access_token（Bearer认证）
        headers = {
            "Authorization": f"Bearer {mc_access_token}"
        }

        async with self.session.get(self._MC_PROFILE_URL, headers=headers) as resp:
            if resp.status == 404:
                raise Exception("该MSA账号未购买Minecraft，无法登录正版游戏")
            if resp.status != 200:
                raise Exception(f"获取个人资料失败: {await resp.text()}")

            profile = await resp.json()
            return {
                "name": profile["name"],
                "id": profile["id"]
            }

    async def _get_minecraft_auth(self, xsts_token: str, user_hash: str) -> dict:
        """获取Minecraft访问令牌（仅返回access_token，用于后续请求个人资料）"""
        payload = {
            "identityToken": f"XBL3.0 x={user_hash};{xsts_token}"
        }

        async with self.session.post(self._MC_AUTH_URL, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"Minecraft认证失败: {await resp.text()}")

            data = await resp.json()
            return {"access_token": data["access_token"]}

    async def add_msa_account(self):
        try:
            username, user_uuid, refresh_token = await self.msa_login()
            self.save_online_account(username, user_uuid, refresh_token)
            print(f"成功添加账户: {username}")
        except Exception as e:
            print(f"登录失败: {str(e)}")

    async def close_session(self):
        if self._is_internal_session and self.session and not self.session.closed:
            await self.session.close()
            self.logger.info("内部创建的ClientSession已关闭")
        elif not self._is_internal_session and self.session:
            self.logger.warning("当前session为外部传入，需由调用者自行关闭")


if __name__ == "__main__":
    async def main():
        account_manager = AccountManager()
        try:
            print("当前账户列表:", account_manager.get_account_list())
            username = input("请输入要刷新的用户名: ")
            await account_manager.refresh_account_token(username)
        finally:
            # 确保无论操作成功/失败，都关闭session
            await account_manager.close_session()

    asyncio.run(main())