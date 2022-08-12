#!/usr/bin/env python3

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path, PurePath
from random import randint
from typing import TYPE_CHECKING, Optional, Union
from urllib.parse import urljoin
from uuid import UUID

import httpx
from attrs import asdict, define, field, validators

import settings

if TYPE_CHECKING:
    from ssl import SSLContext


class BinaryType(Enum):
    WINDOWS = 0
    MACOS = 1
    LINUX = 2


class Status(Enum):
    OK = 0
    INFORMATION = 1
    WARNING = 2
    THREAT = 3


@define(kw_only=True)
class FileDownloadInfo:
    uuid: UUID = field(factory=UUID)
    moduleId: int
    name: str
    size: int
    password: str


@define(kw_only=True)
class FileDownloadStatus:
    currentMachine: str
    status: str


@define
class Operator:
    operator: str = field(
        converter=str.upper, validator=validators.in_(["GT", "GE", "EQ", "LE", "LT", "NE", "LIKE"])
    )
    value: Optional[Union[str, int, datetime]] = None


@define
class Filter:
    filter: str = field(
        validator=validators.in_(
            [
                "banned",
                "binaryType",
                "changeDate",
                "changeType",
                "changedBy",
                "cloudData_age",
                "cloudData_eiPopularity",
                "cloudData_eiReputation",
                "companyName",
                "computersCount",
                "computersSeenCount",
                "connections",
                "dnsEvents",
                "events_average",
                "executableDrops",
                "executionsCount",
                "fileDescription",
                "fileVersion",
                "firstExecuted",
                "firstExecuted",
                "firstSeen",
                "flags_inspected",
                "flags_safe",
                "httpEvents",
                "infosCnt",
                "infosCntUnique",
                "internalName",
                "isDll",
                "lastExecuted",
                "modifiedFiles",
                "modifiedRegistries",
                "moduleName",
                "nearmissTimestamp",
                "Note",
                "originalFileName",
                "outboundSize",
                "packerName",
                "processSignType",
                "processSignerName",
                "productName",
                "productVersion",
                "resolved",
                "sfxName",
                "sha1",
                "signatureCn1",
                "signatureCn2",
                "signatureCn3",
                "signatureCn4",
                "signatureCn5",
                "signatureId",
                "tagId",
                "threatsCnt",
                "threatsCntUnique",
                "unresolved",
                "unresolvedUnique",
                "userId",
                "warningsCnt",
                "warningsCntUnique",
                "whitelistType",
            ]
        )
    )
    operator: Operator


@define
class Or:
    OR: list[Union[Filter, "Or", "And"]]


@define
class And:
    AND: list[Union[Filter, "Or", "And"]]


@define
class FilterTree:
    filterTree: Union[And, Or]

    def to_dict(self):
        return asdict(self, value_serializer=self.filtertree_serializer, recurse=True)

    @staticmethod
    def filtertree_serializer(instance, field, value):

        if isinstance(value, datetime):
            return datetime.strftime(value, "%Y-%m-%d %H:%M:%S")

        if isinstance(value, list):
            new_list = []
            for i in value:

                if isinstance(i, Filter):
                    new_list.append({i.filter: {i.operator.operator: i.operator.value}})

                if isinstance(i, And | Or):
                    new_list.append(i)

            return new_list

        return value


@define
class LocalFilters:
    localFilters: dict
    pageSize: int = 100
    requiredFields: list[str] = ["id"]
    sessionId: int = randint(1, 100000)
    sortOrders: list[dict[str, Union[str, bool]]] = [{"column": "id", "ascend": False}]


class EsetInspect:
    def __init__(
        self,
        username: str,
        password: str,
        url: str,
        domain: bool = False,
        client_id: str = None,
        verify: Union[bool, str, "SSLContext"] = True,
    ) -> None:
        self.username = username
        self.password = password
        self.domain = domain
        self.url = url
        self.client_id = client_id
        self.client = httpx.AsyncClient(
            timeout=60,
            verify=verify,
            cookies={"CLIENT_ID": self.client_id} if self.client_id else {},
        )
        self._token = ""

        if self.is_cloud and not client_id:
            raise ValueError("Cloud instances of ESET Inspect need a client ID.")

    async def __aenter__(self):
        await self.authenticate()
        return self

    async def __aexit__(self, *args):
        await self.logout()
        await self.client.aclose()

    @property
    def is_cloud(self) -> bool:
        return self.url.endswith(".inspect.eset.com")

    async def authenticate(self) -> None:
        json_data = {"username": self.username, "password": self.password, "domain": self.domain}
        await self.api_call("authenticate", "POST", json_data)

    async def logout(self) -> None:
        json_data = {"token": self._token}
        await self.frontend_call("logout", "POST", json_data)

    def _update_token(self, token: str) -> None:
        self._token = token
        self.client.headers.update({"Authorization": f"Bearer {token}"})

    async def _raw_request(
        self, uri: str, method: str = "GET", json_data: dict = None
    ) -> httpx.Response:

        if method.lower() not in ["get", "post"]:
            raise ValueError(f"Invalid method '{method}'")

        url = urljoin(self.url, uri)
        httpreq = getattr(self.client, method.lower())

        async with limit:
            kwargs = {"json": json_data} if method.lower() != "get" else {}
            resp = await httpreq(url, **kwargs)
            resp.raise_for_status()

            if "x-security-token" in resp.headers:
                self._update_token(resp.headers["x-security-token"])

            return resp

    async def api_call(
        self, endpoint: str, method: str = "GET", json_data: dict = None
    ) -> httpx.Response:
        uri = urljoin("/api/v1/", endpoint.lstrip("/"))

        return await self._raw_request(uri, method, json_data=json_data)

    async def frontend_call(
        self, endpoint: str, method: str = "GET", json_data: dict = None
    ) -> httpx.Response:
        uri = urljoin("/frontend/", endpoint.lstrip("/"))

        async with asyncio.Semaphore(3):
            return await self._raw_request(uri, method, json_data=json_data)

    async def executables(
        self,
        filter_tree: FilterTree,
    ) -> list:

        page = 0
        local_filters = LocalFilters(filter_tree.to_dict())

        page_resp = await self.frontend_call(f"executables/{page}", "POST", asdict(local_filters))
        page_json = page_resp.json()
        total_count = page_json["totalCount"]
        entities = page_json["entities"]

        print(f"Found {total_count} executables that match your filter")

        page += 1

        # Handle multiple pages
        tasks = set()
        while local_filters.pageSize * page < total_count:
            task = asyncio.create_task(
                self.frontend_call(f"executables/{page}", "POST", asdict(local_filters))
            )
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            page += 1

        result = await asyncio.gather(*tasks)
        for response in result:
            entities += response.json()["entities"]

        return entities

    async def download_file(self, module_id: int, output_directory: str) -> None:

        Path(output_directory).mkdir(parents=True, exist_ok=True)

        resp = await self.frontend_call(f"download/start/{module_id}")
        file_info = FileDownloadInfo(**resp.json())
        filename = PurePath(file_info.name)

        while True:
            resp = await self.frontend_call(f"download/status", "POST", {"uuid": file_info.uuid})
            download_status = FileDownloadStatus(**resp.json())

            if download_status and download_status.status == "NoClientFound":
                print(f"File not found on network: {filename} ({module_id})")
                return

            if download_status and download_status.status == "FileReady":
                print(
                    f"Found file {filename} ({module_id}) on machine {download_status.currentMachine}"
                )

                uri = urljoin("/download/", f"{file_info.uuid}/{filename.stem}.zip")
                downloaded_file = await self._raw_request(uri)

                download_path = Path(
                    output_directory, f"{filename}_{module_id}_({file_info.password}).zip"
                )

                with open(download_path, "wb") as f:
                    f.write(downloaded_file.content)

                break

            await asyncio.sleep(1)

    async def download_files(self, entities: list, output_directory: str) -> None:
        tasks = set()
        for entity in entities:
            task = asyncio.create_task(self.download_file(entity["id"], output_directory))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        await asyncio.gather(*tasks)


class PreDefinedFilters(Enum):
    RISK_LEVEL_5 = FilterTree(
        And(
            [
                Or(
                    [
                        Filter("binaryType", Operator("EQ", BinaryType.WINDOWS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.MACOS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.LINUX.value)),
                    ]
                ),
                Filter("isDll", Operator("EQ", 0)),
                Filter("banned", Operator("EQ", 0)),
                Filter("flags_safe", Operator("EQ", 0)),
                Filter("computersCount", Operator("GE", 1)),
                Filter("cloudData_eiReputation", Operator("LE", 6)),
                Filter("cloudData_eiPopularity", Operator("LE", 4)),
                Filter("connections", Operator("GE", 0)),
                Filter("processSignType", Operator("LE", 70)),
            ]
        )
    )
    POPULARITY_1_COMPUTERS_1 = FilterTree(
        And(
            [
                Or(
                    [
                        Filter("binaryType", Operator("EQ", BinaryType.WINDOWS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.MACOS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.LINUX.value)),
                    ]
                ),
                Filter("cloudData_eiPopularity", Operator("LE", 4)),
                And(
                    [
                        Filter("computersCount", Operator("GE", 1)),
                        Filter("computersCount", Operator("LT", 2)),
                    ]
                ),
            ]
        )
    )
    SEEN_ONLY_IN_THIS_COMPANY = FilterTree(
        And(
            [
                Or(
                    [
                        Filter("binaryType", Operator("EQ", BinaryType.WINDOWS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.MACOS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.LINUX.value)),
                    ]
                ),
                Filter("isDll", Operator("EQ", 0)),
                Filter("banned", Operator("EQ", 0)),
                Filter("flags_safe", Operator("EQ", 0)),
                Filter("cloudData_eiPopularity", Operator("EQ", 0)),
            ]
        )
    )
    FIRST_EXECUTED_TODAY = FilterTree(
        And(
            [
                Or(
                    [
                        Filter("binaryType", Operator("EQ", BinaryType.WINDOWS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.MACOS.value)),
                        Filter("binaryType", Operator("EQ", BinaryType.LINUX.value)),
                    ]
                ),
                Filter("isDll", Operator("EQ", 0)),
                Filter("banned", Operator("EQ", 0)),
                Filter("flags_safe", Operator("EQ", 0)),
                Filter("firstExecuted", Operator("GE", datetime.now() - timedelta(days=1))),
            ]
        )
    )


async def main() -> None:
    # filter = FilterTree(Or([Filter("moduleName", Operator("LIKE", "powershell_ise"))]))
    filter = PreDefinedFilters.FIRST_EXECUTED_TODAY.value

    async with EsetInspect(
        settings.USERNAME,
        settings.PASSWORD,
        settings.URL,
        domain=settings.DOMAIN,
        verify=settings.VERIFY,
    ) as ei:
        entities = await ei.executables(filter)

        await ei.download_files(entities, "out")


if __name__ == "__main__":
    limit = asyncio.Semaphore(25)
    asyncio.run(main())
