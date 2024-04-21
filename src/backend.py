import logging
import json
import time
import xml.etree.ElementTree as ET
from collections import namedtuple
from datetime import datetime
from typing import Dict, List, NewType, Optional, Set, Any, Tuple

import aiohttp
from galaxy.api.errors import (
    AccessDenied, AuthenticationRequired, BackendError, BackendNotAvailable, BackendTimeout, NetworkError,
    UnknownBackendResponse
)
from galaxy.api.types import Achievement, SubscriptionGame, Subscription
from galaxy.http import HttpClient
from yarl import URL


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


MasterTitleId = NewType("MasterTitleId", str)
AchievementSet = NewType("AchievementSet", str)
OfferId = NewType("OfferId", str)
Timestamp = NewType("Timestamp", int)
Json = Dict[str, Any]  # helper alias for general purpose

SubscriptionDetails = namedtuple('SubscriptionDetails', ['tier', 'end_time'])


class CookieJar(aiohttp.CookieJar):
    def __init__(self):
        super().__init__()
        self._cookies_updated_callback = None

    def set_cookies_updated_callback(self, callback):
        self._cookies_updated_callback = callback

    def update_cookies(self, cookies, url=URL()):
        super().update_cookies(cookies, url)
        if cookies and self._cookies_updated_callback:
            self._cookies_updated_callback(list(self))


class AuthenticatedHttpClient(HttpClient):
    def __init__(self):
        self._auth_lost_callback = None
        self._cookie_jar = CookieJar()
        self._access_token = None
        self._last_access_token_success = None
        self._save_lats_callback = None
        super().__init__(cookie_jar=self._cookie_jar)

    def set_auth_lost_callback(self, callback):
        self._auth_lost_callback = callback

    def set_cookies_updated_callback(self, callback):
        self._cookie_jar.set_cookies_updated_callback(callback)

    async def authenticate(self, cookies):
        self._cookie_jar.update_cookies(cookies)
        await self._get_access_token()

    def is_authenticated(self):
        return self._access_token is not None

    async def get(self, *args, **kwargs):
        if not self._access_token:
            raise AccessDenied("No access token")

        try:
            return await self._authorized_get(*args, **kwargs)
        except (AuthenticationRequired, AccessDenied):
            # Origin backend returns 403 when the auth token expires
            await self._refresh_token()
            return await self._authorized_get(*args, **kwargs)

    async def _authorized_get(self, *args, **kwargs):
        headers = kwargs.setdefault("headers", {})
        headers["Authorization"] = "Bearer {}".format(self._access_token)
        headers["AuthToken"] = self._access_token
        headers["X-AuthToken"] = self._access_token

        return await super().request("GET", *args, **kwargs)

    async def _refresh_token(self):
        try:
            await self._get_access_token()
        except (BackendNotAvailable, BackendTimeout, BackendError, NetworkError):
            logger.warning("Failed to refresh token for independent reasons")
            raise
        except Exception:
            logger.exception("Failed to refresh token")
            self._access_token = None
            if self._auth_lost_callback:
                self._auth_lost_callback()
            raise AccessDenied("Failed to refresh token")

    async def _get_access_token(self):
        # upd 18.09.2023 : sounds like a flaw ?
        # the key is in the "Location" header, no redirection needed. as it's a qrc:// request (QT) it won't work with aiohttp
        url = "https://accounts.ea.com/connect/auth"
        params = {
            "client_id": "JUNO_PC_CLIENT",
            "nonce": "nonce",
            "display": "junoWeb/login",
            "response_type": "token",
            "redirectUri": "nucleus:rest",
            "prompt": "none"
        }
        response = await super().request("GET", url, params=params, allow_redirects=False)

        # upd 18.09.2023 : the access_token is in the "Location" header. It's a Bearer token.
        try:
            data = response.headers["Location"]
            # should look like qrc:/html/login_successful.html#access_token=
            # note that there's some other parameters afterwards, so we need to isolate the variable well
            self._access_token = data.split("#")[1].split("=")[1].split("&")[0]
            # tokens expire after 4 hours, written in seconds (written in the qrc:// url itself, last parameter)
            # so we need to save the time of the last successful login
            # this is used to determine if the token is still valid or not
            # if it's not, we need to refresh it
            validity = data.split("#")[1].split("=")[3].split("&")[0]
            self._save_lats_callback = int(time.time()) + int(validity)
        except (TypeError, ValueError, KeyError) as e:
            self._log_session_details()
            try:
                # in the case of qrc:/html/login_required.html#error=login_required
                if data.split("#")[1].split("=")[1].split('&')[0] == "login_required":
                    raise AuthenticationRequired
                else:
                    raise UnknownBackendResponse(data)
            except AttributeError:
                logger.exception(f"Error parsing access token: {repr(e)}, data: {data}")
                raise UnknownBackendResponse

    # more logging for auth lost investigation

    def _save_lats(self):
        if self._save_lats_callback is not None:
            self._last_access_token_success = int(time.time())
            self._save_lats_callback(self._last_access_token_success)

    def set_save_lats_callback(self, callback):
        self._save_lats_callback = callback

    def load_lats_from_cache(self, value: Optional[str]):
        self._last_access_token_success = int(value) if value else None

    def _log_session_details(self):
        try:
            utag_main_cookie = next(filter(lambda c: c.key == 'utag_main', self._cookie_jar))
            utag_main = {i.split(':')[0]: i.split(':')[1] for i in utag_main_cookie.value.split('$')}
            logger.info('now: %s st: %s ses_id: %s lats: %s',
                str(int(time.time())),
                utag_main['_st'][:10],
                utag_main['ses_id'][:10],
                str(self._last_access_token_success)
            )
        except Exception as e:
            logger.warning('Failed to get session duration: %s', repr(e))


class OriginBackendClient:
    def __init__(self, http_client):
        self._http_client = http_client

    # Juno API
    @staticmethod
    def _get_api_host():
        return "https://service-aggregation-layer.juno.ea.com/graphql"
    
    # Origin (old) API
    @staticmethod
    def _get_origin_host():
        return "https://api1.origin.com"

    # Only applies to the Juno API. Needed to access certain API endpoints, or else we're refused.
    @staticmethod
    def _get_persisted_query_status():
        return "&extensions={\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"575a85abf94ca1c4c71dd422d536cb15b02c94ac720459e3b7f9750097f9153f\"}}"

    async def get_identity(self) -> Tuple[str, str, str]:
        pid_response = await self._http_client.get("https://gateway.ea.com/proxy/identity/pids/me")
        
        data = await pid_response.json()
        user_id = data["pid"]["pidId"]

        persona_id_response = await self._http_client.get(
            "{}?operationName=GetPlayerByPdLite&variables={{\"isMutualFriendsEnabled\":false,\"pd\":\"{}\"}}{}".format(self._get_api_host(), user_id, self._get_persisted_query_status())
        )
        content = await persona_id_response.json()
        logger.info("Retrieved content: " + json.dumps(content))

        try:
            persona_id = content["data"]["playerByPd"]["psd"]
            user_name = content["data"]["playerByPd"]["displayName"]

            return str(user_id), str(persona_id), str(user_name)
        except (ET.ParseError, AttributeError) as e:
            logger.exception("Can not parse backend response: %s, error %s", content, repr(e))
            raise UnknownBackendResponse()

    async def get_entitlements(self, user_id) -> List[Json]:
        url = "{}/ecommerce2/consolidatedentitlements/{}?machine_hash=1".format(
            self._get_origin_host(),
            user_id
        )
        headers = {
            "Accept": "application/vnd.origin.v3+json; x-cache/force-write"
        }
        response = await self._http_client.get(url, headers=headers)
        try:
            data = await response.json()
            logger.debug(json.dumps(data))
            return data["entitlements"]
        except (ValueError, KeyError) as e:
            logger.exception("Can not parse backend response: %s, error %s", await response.text(), repr(e))
            raise UnknownBackendResponse()

    async def get_offer(self, offer_id) -> Json:
        url = "{}/ecommerce2/public/supercat/{}/{}".format(
            self._get_origin_host(),
            offer_id,
            "en_US"
        )
        response = await self._http_client.get(url)
        try:
            return await response.json()
        except ValueError as e:
            logger.exception("Can not parse backend response: %s, error %s", await response.text, repr(e))
            raise UnknownBackendResponse()

    async def get_achievements(self, persona_id: str, achievement_set: str = None) \
            -> Dict[AchievementSet, List[Achievement]]:

        response = await self._http_client.get(
            "https://achievements.gameservices.ea.com/achievements/personas/{persona_id}{ach_set}/all".format(
                persona_id=persona_id, ach_set=("/" + achievement_set) if achievement_set else ""
            ),
            params={
                "lang": "en_US",
                "metadata": "true"
            }
        )

        '''
        'all' format:
        "50317_185353_50844": {
            "platform": "PC Origin",
            "achievements": {"1": {"complete": True, "u": 1376676315, "name": "Stranger in a Strange Land"}},
            "expansions": [{"id": "222", "name": "Prestige and Speedlists"}],
            "name": "Need for Speed™"
        }

        'specific' format:
        {"1": {"complete": True, "u": 1376676315, "name": "Stranger in a Strange Land"}}
        '''

        def parser(json_data: Dict) -> List[Achievement]:
            return [
                Achievement(achievement_id=key, achievement_name=value["name"], unlock_time=value["u"])
                for key, value in json_data.items() if value.get("complete")
            ]

        try:
            json = await response.json()
            if achievement_set is not None:
                return {AchievementSet(achievement_set): parser(json)}

            return {
                AchievementSet(achievement_set): parser(info.get("achievements", {}))
                for achievement_set, info in json.items()
            }

        except (ValueError, KeyError) as e:
            logger.exception("Can not parse achievements from backend response %s", repr(e))
            raise UnknownBackendResponse()

    async def get_game_time(self, user_id, master_title_id, multiplayer_id):
        url = "{}/atom/users/{}/games/{}/usage".format(
            self._get_origin_host(),
            user_id,
            master_title_id
        )

        # 'multiPlayerId' must be used if exists, otherwise '**/lastplayed' backend returns zero
        headers = {}
        if multiplayer_id:
            headers["Multiplayerid"] = multiplayer_id

        response = await self._http_client.get(url, headers=headers)

        """
        response looks like following:
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <usage>
            <gameId>192140</gameId>
            <total>30292</total>
            <MultiplayerId>1024390</MultiplayerId>
            <lastSession>9</lastSession>
            <lastSessionEndTimeStamp>1497190184759</lastSessionEndTimeStamp>
        </usage>
        """
        try:
            def parse_last_played_time(lastplayed_timestamp) -> Optional[int]:
                if lastplayed_timestamp is None:
                    return None
                return round(int(lastplayed_timestamp.text) / 1000) or None  # response is in miliseconds

            content = await response.text()
            xml_response = ET.fromstring(content)
            total_play_time = round(int(xml_response.find("total").text) / 60)  # response is in seconds

            return total_play_time, parse_last_played_time(xml_response.find("lastSessionEndTimeStamp"))
        except (ET.ParseError, AttributeError, ValueError) as e:
            logger.exception("Can not parse backend response: %s, %s", await response.text(), repr(e))
            raise UnknownBackendResponse()

    async def get_friends(self, user_id):
        response = await self._http_client.get(
            "{base_api}?operationName=GetPlayerFriends&variables={{\"mutualFriendsOffset\":0,\"mutualFriendsLimit\":0,\"isMutualFriendsEnabled\":false,\"pd\":\"{userid}\",\"offset\":0,\"limit\":0}}{extension}".format(
                base_api=self._get_api_host(),
                userid=user_id,
                extension=self._get_persisted_query_status()
            )
        )

        """
        {
            "data": {
                "playerByPd": {
                "id": "...",
                "pd": "...",
                "friends": {
                    "totalCount": 1,
                    "hasNextPage": false,
                    "hasPreviousPage": false,
                    "items": [
                    {
                        "id": "...",
                        "pd": "...",
                        "player": {
                        "id": "...",
                        "pd": "...",
                        "psd": "...",
                        "displayName": "User",
                        "uniqueName": "User",
                        "nickname": "User",
                        "avatar": {
                            "large": {
                            "height": 416,
                            "width": 416,
                            "path": "https://secure.download.dm.origin.com/production/avatar/prod/1/599/416x416.JPEG",
                            "__typename": "Image"
                            },
                            "medium": {
                            "height": 208,
                            "width": 208,
                            "path": "https://secure.download.dm.origin.com/production/avatar/prod/1/599/208x208.JPEG",
                            "__typename": "Image"
                            },
                            "small": {
                            "height": 40,
                            "width": 40,
                            "path": "https://secure.download.dm.origin.com/production/avatar/prod/1/599/40x40.JPEG",
                            "__typename": "Image"
                            },
                            "__typename": "AvatarList"
                        },
                        "relationship": "FRIEND",
                        "__typename": "Player"
                        },
                        "source": "GLOBAL",
                        "__typename": "Friend"
                    },
                    ],
                    "__typename": "FriendsOffsetPage"
                },
                "__typename": "Player"
                }
            }
        }
        """

        try:
            content = await response.json()
            return {
                user_json["id"]: user_json["pd"]
                for user_json in content["data"]["playerByPd"]["friends"]["items"]
            }
        except (AttributeError, ValueError):
            logger.exception("Can not parse backend response: %s", await response.text())
            raise UnknownBackendResponse()

    async def get_lastplayed_games(self, user_id) -> Dict[MasterTitleId, Timestamp]:
        response = await self._http_client.get("{base_api}/atom/users/{user_id}/games/lastplayed".format(
            base_api=self._get_origin_host(),
            user_id=user_id
        ))

        '''
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <lastPlayedGames>
            <userId>1008620950926</userId>
            <lastPlayed>
                <masterTitleId>180975</masterTitleId>
                <timestamp>2019-05-17T14:45:48.001Z</timestamp>
            </lastPlayed>
        </lastPlayedGames>
        '''

        def parse_title_id(product_info_xml) -> MasterTitleId:
            return product_info_xml.find("masterTitleId").text

        def parse_timestamp(product_info_xml) -> Timestamp:
            formats = (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ"  # no microseconds
            )
            td = product_info_xml.find("timestamp").text
            for date_format in formats:
                try:
                    time_delta = datetime.strptime(td, date_format) - datetime(1970, 1, 1)
                except ValueError:
                    continue
                return Timestamp(int(time_delta.total_seconds()))
            raise ValueError(f"time data '{td}' does not match known formats")

        try:
            content = await response.text()
            return {
                parse_title_id(product_info_xml): parse_timestamp(product_info_xml)
                for product_info_xml in ET.ElementTree(ET.fromstring(content)).iter("lastPlayed")
            }
        except (ET.ParseError, AttributeError, ValueError) as e:
            logger.exception("Can not parse backend response: %s", await response.text())
            raise UnknownBackendResponse(e)

    async def get_favorite_games(self, user_id) -> Set[OfferId]:
        response = await self._http_client.get("{base_api}/atom/users/{user_id}/privacySettings/FAVORITEGAMES".format(
            base_api=self._get_api_host(),
            user_id=user_id
        ))

        '''
        <?xml version="1.0" encoding="UTF-8"?>
        <privacySettings>
           <privacySetting>
              <userId>1008620950926</userId>
              <category>FAVORITEGAMES</category>
              <payload>OFB-EAST:48217;OFB-EAST:109552409;DR:119971300</payload>
           </privacySetting>
        </privacySettings>
        '''

        try:
            content = await response.text()
            payload_xml = ET.ElementTree(ET.fromstring(content)).find("privacySetting/payload")
            if payload_xml is None or payload_xml.text is None:
                # No games tagged, if on object evaluates to false
                return set()

            favorite_games = set(OfferId(payload_xml.text.split(';')))

            return favorite_games
        except (ET.ParseError, AttributeError, ValueError):
            logger.exception("Can not parse backend response: %s", await response.text())
            raise UnknownBackendResponse()

    async def get_hidden_games(self, user_id) -> Set[OfferId]:
        response = await self._http_client.get("{base_api}/atom/users/{user_id}/privacySettings/HIDDENGAMES".format(
            base_api=self._get_api_host(),
            user_id=user_id
        ))

        '''
        <?xml version="1.0" encoding="UTF-8"?>
        <privacySettings>
           <privacySetting>
              <userId>1008620950926</userId>
              <category>HIDDENGAMES</category>
              <payload>1.0|OFB-EAST:109552409;OFB-EAST:109552409</payload>
           </privacySetting>
        </privacySettings>
        '''

        try:
            content = await response.text()
            payload_xml = ET.ElementTree(ET.fromstring(content)).find("privacySetting/payload")
            if payload_xml is None or payload_xml.text is None:
                # No games tagged, if on object evaluates to false
                return set()
            payload_text = payload_xml.text.replace('1.0|', '')
            hidden_games = set(OfferId(payload_text.split(';')))

            return hidden_games
        except (ET.ParseError, AttributeError, ValueError):
            logger.exception("Can not parse backend response: %s", await response.text())
            raise UnknownBackendResponse()

    def _get_subscription_status(self, response_data: Dict) -> Optional[str]:
        try:
            return response_data['Subscription']['status'].lower() if response_data else None
        except (ValueError, KeyError) as e:
            logger.exception("No 'status' key in response", response_data, repr(e))
            raise UnknownBackendResponse()

    async def _get_active_subscription(self, subscription_uri) -> Optional[SubscriptionDetails]:
        def parse_timestamp(timestamp: str) -> Timestamp:
            return Timestamp(
                int((datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S") - datetime(1970, 1, 1)).total_seconds()))

        response = await self._http_client.get(subscription_uri)
        try:
            data = await response.json()
            sub_status = self._get_subscription_status(data)
            if data and sub_status == 'enabled':
                return SubscriptionDetails(
                    tier=data['Subscription']['subscriptionLevel'].lower(),
                    end_time=parse_timestamp(data['Subscription']['nextBillingDate'])
                )
            else:
                logger.debug(f"Cannot get data from response or subscription status is not 'ENABLED': {data}")
                return None
        except (ValueError, KeyError) as e:
            logger.exception("Can not parse backend response while getting subs details: %s, error %s", await response.text(), repr(e))
            raise UnknownBackendResponse()

    async def _get_subscription_uris(self, user_id) -> List[str]:
        url = f"https://gateway.ea.com/proxy/subscription/pids/{user_id}/subscriptionsv2/groups/Origin Membership"
        response = await self._http_client.get(url)
        try:
            data = await response.json()
            return [
                f"https://gateway.ea.com/proxy/subscription/pids/{user_id}{path}"
                for path in data.get('subscriptionUri', [])
            ]
        except (ValueError, KeyError) as e:
            logger.exception("Can not parse backend response while getting subs uri: %s, error %s", await response.text(), repr(e))
            raise UnknownBackendResponse()

    async def get_subscriptions(self, user_id) -> List[Subscription]:
        subs = {'standard': Subscription(subscription_name='EA Play', owned=False),
                'premium': Subscription(subscription_name='EA Play Pro', owned=False)}
        for uri in await self._get_subscription_uris(user_id):
            user_sub = await self._get_active_subscription(uri)
            if user_sub:
                break
        else:
            user_sub = None
        logger.debug(f'user_sub: {user_sub}')
        try:
            if user_sub:
                subs[user_sub.tier].owned = True
                subs[user_sub.tier].end_time = user_sub.end_time
        except (ValueError, KeyError) as e:
            logger.exception("Unknown subscription tier, error %s", repr(e))
            raise UnknownBackendResponse()
        return [subs['standard'], subs['premium']]

    async def get_games_in_subscription(self, tier) -> List[SubscriptionGame]:
        """
            Note: `game_id` of an returned subscription game may not match with `game_id` of the game added to user library!
        """
        url = f"{self._get_origin_host()}/ecommerce2/vaultInfo/Origin Membership/tiers/{tier}"
        headers = {
            "Accept": "application/vnd.origin.v3+json; x-cache/force-write"
        }
        response = await self._http_client.get(url, headers=headers)
        try:
            games = await response.json()
            subscription_suffix = '@subscription'  # externalType for compatibility with owned games interface
            return [
                SubscriptionGame(
                    game_title=game['displayName'],
                    game_id=game['offerId'] + subscription_suffix
                ) for game in games['game']
            ]
        except (ValueError, KeyError) as e:
            logger.exception("Can not parse backend response while getting subs games: %s, error %s", await response.text(), repr(e))
            raise UnknownBackendResponse()
