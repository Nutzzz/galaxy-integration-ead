import logging
import json
import random
import sys
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
        # the key is in the "Location" header, no redirection needed.
        url = "https://accounts.ea.com/connect/auth"
        params = {
            "client_id": "JUNO_PC_CLIENT",
            "display": "junoWeb/login",
            "response_type": "token",
            "redirectUri": "nucleus:rest"
        }
        response = await super().request("GET", url, params=params, allow_redirects=False)

        # upd 18.09.2023 : the access_token is in the "Location" header. It's a Bearer token.
        if "access_token" in response.headers["Location"]:
            data = response.headers["Location"]
            # should look like qrc:/html/login_successful.html#access_token=
            # note that there's some other parameters afterwards, so we need to isolate the variable well
            self._access_token = data.split("#")[1].split("=")[1].split("&")[0]
        elif "access_token" not in response.headers["Location"] and "error=login_required" in response.headers["Location"]:
            self._log_session_details()
            raise AuthenticationRequired("Error parsing access token. Must reauthenticate.")
        else:
            self._save_lats()

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
        return "https://api{}.origin.com".format(random.randint(1, 4))

    async def get_identity(self) -> Tuple[str, str, str]:
        url = "{}?query=query{{ me {{ player {{ pd psd displayName }} }} }}".format(self._get_api_host())
        pid_response = await self._http_client.get(url)
        data = await pid_response.json()
        logger.info("Getting identity: %s", data)

        try:
            user_id = data["data"]["me"]["player"]["pd"]
            persona_id = data["data"]["me"]["player"]["psd"]
            user_name = data["data"]["me"]["player"]["displayName"]

            return str(user_id), str(persona_id), str(user_name)
        except (AttributeError, KeyError) as e:
            logger.exception("Can not parse backend response: %s, error %s", data, repr(e))
            raise UnknownBackendResponse()

    async def get_entitlements(self) -> List[Json]:
        if sys.platform == 'win32':
            url = "{}?operationName=getPreloadedOwnedGames&variables={{\"isMac\":false,\"locale\":\"fr\",\"limit\":5000,\"next\":\"0\",\"type\":[\"DIGITAL_FULL_GAME\",\"PACKAGED_FULL_GAME\"],\"entitlementEnabled\":true,\"storefronts\":[\"EA\",\"STEAM\",\"EPIC\"],\"ownershipMethods\":[\"UNKNOWN\",\"ASSOCIATION\",\"PURCHASE\",\"REDEMPTION\",\"GIFT_RECEIPT\",\"ENTITLEMENT_GRANT\",\"DIRECT_ENTITLEMENT\",\"PRE_ORDER_PURCHASE\",\"VAULT\",\"XGP_VAULT\",\"STEAM\",\"STEAM_VAULT\",\"STEAM_SUBSCRIPTION\",\"EPIC\",\"EPIC_VAULT\",\"EPIC_SUBSCRIPTION\"],\"platforms\":[\"PC\"]}}&extensions={{\"persistedQuery\":{{\"version\":1,\"sha256Hash\":\"a2b36612157ecaa1a40aa5508d96137ce27c4c344d21dcb6d4feec7f47739fb3\"}}}}".format(
                self._get_api_host()
            )
        elif sys.platform == 'darwin':
            url = "{}?operationName=getPreloadedOwnedGames&variables={{\"isMac\":true,\"locale\":\"fr\",\"limit\":5000,\"next\":\"0\",\"type\":[\"DIGITAL_FULL_GAME\",\"PACKAGED_FULL_GAME\"],\"entitlementEnabled\":true,\"storefronts\":[\"EA\",\"STEAM\",\"EPIC\"],\"ownershipMethods\":[\"UNKNOWN\",\"ASSOCIATION\",\"PURCHASE\",\"REDEMPTION\",\"GIFT_RECEIPT\",\"ENTITLEMENT_GRANT\",\"DIRECT_ENTITLEMENT\",\"PRE_ORDER_PURCHASE\",\"VAULT\",\"XGP_VAULT\",\"STEAM\",\"STEAM_VAULT\",\"STEAM_SUBSCRIPTION\",\"EPIC\",\"EPIC_VAULT\",\"EPIC_SUBSCRIPTION\"],\"platforms\":[\"PC\"]}}&extensions={{\"persistedQuery\":{{\"version\":1,\"sha256Hash\":\"a2b36612157ecaa1a40aa5508d96137ce27c4c344d21dcb6d4feec7f47739fb3\"}}}}".format(
                self._get_api_host()
            )
        response = await self._http_client.get(url)
        try:
            data = await response.json()
            return data['data']['me']['ownedGameProducts']['items']
        except (ValueError, KeyError) as e:
            logger.exception("Can not parse backend response: %s, error %s", await response.text(), repr(e))
            raise UnknownBackendResponse()
    
    async def get_offer(self, game_slug) -> Json:
        if sys.platform == 'win32':
            url = "{}?operationName=getUserOwnedProduct&variables={{\"isMac\":false,\"offerIds\":[\"{}\"],\"storefronts\":[\"EA\",\"STEAM\",\"EPIC\"]}}&extensions={{\"persistedQuery\":{{\"version\":1,\"sha256Hash\":\"36a83accd60d006be3805448e028b73656d578c6bd93b88efdae5e20f9b35853\"}}}}".format(
                self._get_api_host(),
                game_slug
            )
        elif sys.platform == 'darwin':
            url = "{}?operationName=getUserOwnedProduct&variables={{\"isMac\":true,\"offerIds\":[\"{}\"],\"storefronts\":[\"EA\",\"STEAM\",\"EPIC\"]}}&extensions={{\"persistedQuery\":{{\"version\":1,\"sha256Hash\":\"36a83accd60d006be3805448e028b73656d578c6bd93b88efdae5e20f9b35853\"}}}}".format(
                self._get_api_host(),
                game_slug
            )

        response = await self._http_client.get(url)
        try:
            return await response.json()
        except ValueError as e:
            logger.exception("Can not parse backend response: %s, error %s", await response.text, repr(e))
            raise UnknownBackendResponse()

    async def get_achievements(self, offer_id: OfferId, persona_id) -> Dict[AchievementSet, List[Achievement]]:
        url = "{}?operationName=ownedGameAchievements&variables={{\"offerId\":\"{}\",\"playerPsd\":\"{}\",\"locale\":\"en\"}}&extensions={{\"persistedQuery\":{{\"version\":1,\"sha256Hash\":\"1c6280579cd6b172787735e8efacb21e62dc08039115720254d8948922016277\"}}}}".format(
                self._get_api_host(),
                offer_id,
                persona_id
            ),
        response = await self._http_client.get(url)

        '''
        (heavily simplified, but you get the idea, right... right ?)
        {
        "data": {
            "achievements": [
                {
                    "id": "51302_190132_50844",
                    "achievements": [
                        {
                            "id": "bc8deacf866d90904a0506f0659bedf71f44775e",
                            "name": "Operations",
                            "description": "Win 1 round of Operations in multiplayer",
                            "awardCount": 0,
                            "howTo": "",
                            "images": [
                                {
                                    "path": "https://achievements.gameservices.ea.com/achievements/icons/51302_190132_50844-1-40.png",
                                    "__typename": "Image"
                                },
                                {
                                    "path": "https://achievements.gameservices.ea.com/achievements/icons/51302_190132_50844-1-208.png",
                                    "__typename": "Image"
                                },
                                {
                                    "path": "https://achievements.gameservices.ea.com/achievements/icons/51302_190132_50844-1-416.png",
                                    "__typename": "Image"
                                }
                            ],
                            "__typename": "Achievement"
                        }
                    ]
                }
            ]
        }
        '''

        def parser(json_data: Dict) -> List[Achievement]:
            achievements = []
            try:
                for achievement in json_data["achievements"]:
                    if achievement["awardCount"] == 1:
                        achievement_data = {
                            "id": achievement["id"],
                            "name": achievement["name"],
                            "unlock_time": time.time()
                        }
                    achievements.append(achievement_data)
            except KeyError as e:
                logger.exception("Can not parse achievements from backend response %s", repr(e))
                raise UnknownBackendResponse()
            return achievements

        try:
            json = await response.json()
            achievement_sets = []
            for achievement_set in json["data"]["achievements"]:
                achievements = parser(achievement_set)
                achievement_sets.append(achievements)
            return achievement_sets

        except (ValueError, KeyError) as e:
            logger.exception("Can not parse achievements from backend response %s", repr(e))
            raise UnknownBackendResponse()

        
    async def get_achievement_set(self, offer_id: OfferId, persona_id) -> str:
        url = "{}?query=query {{achievements(offerId:\"{}\",playerPsd:\"{}\"){{id}}}}".format(
                self._get_api_host(),
                offer_id,
                persona_id
            )
        
        response = await self._http_client.get(url)
       
        try:
            logger.info("Data: %s", await response.text())
            json = await response.json()
            achievements = json["data"]["achievements"]
            if achievements:
                return achievements[0]["id"] if "id" in achievements[0] else None
            else:
                return None

        except (ValueError, KeyError) as e:
            logger.exception("Can not parse achievements from backend response %s", repr(e))
            raise UnknownBackendResponse()

    async def get_game_time(self, game_slug):
        url = "{}?query=query {{me {{recentGames(gameSlugs:\"{}\"){{items {{lastSessionEndDate totalPlayTimeSeconds}}}}}}}}".format(
            self._get_api_host(),
            game_slug
        )

        response = await self._http_client.get(url)

        """
        example response:
        {
            "data": {
                "me": {
                "recentGames": {
                    "items": [
                        {
                            "lastSessionEndDate": "2024-02-29T16:00:23.000Z",
                            "totalPlayTimeSeconds": 791005,
                        }
                    ],
                },
                }
            }
        }
        """
        try:
            def parse_last_played_time(lastplayed_timestamp) -> Optional[int]:
                if lastplayed_timestamp is None:
                    return None
                return round(int(lastplayed_timestamp.text) / 1000) or None  # response is in miliseconds

            content = await response.json()
            # assuming this is just EA's way of saying we never played a game.
            if not content['data']['me']['recentGames']['items']:
                return 0, None
            else:
                total_play_time = round(int(content['data']['me']['recentGames']['items'][0]['totalPlayTimeSeconds'].text) / 60)  # response is in seconds
                last_played_time = parse_last_played_time(content['data']['me']['recentGames']['items'][0]['lastSessionEndDate'])

            return total_play_time, last_played_time
        except (AttributeError, ValueError, KeyError) as e:
            logger.exception("Can not parse backend response: %s, %s", await response.text(), repr(e))
            raise UnknownBackendResponse()

    async def get_friends(self):
        response = await self._http_client.get(
            "{}?query=query{{me {{friends {{items {{player {{pd psd displayName}}}}}}}}}}".format(
                self._get_api_host()
            )
        )

        """
        {
            "data": {
                "me": {
                    "friends": {
                        "items": [
                            {
                                "player": {
                                    "pd": "...",
                                    "psd": "...",
                                    "displayName": "User"
                                }
                            }
                        ]
                    }
                }
            }
        }
        """

        try:
            content = await response.json()
            return {
                user_json['player']['pd']: user_json["player"]["displayName"]
                for user_json in content["data"]["me"]["friends"]["items"]
            }
        except (AttributeError, KeyError):
            logger.exception("Can not parse backend response: %s", await response.text())
            raise UnknownBackendResponse()

    # Doesn't seem to exist as-is in EA Desktop, does appear in an endpoint response. Might be subject to subsequent rework.
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

    # Doesn't exist in EA Desktop, meant to disappear soon.
    async def get_favorite_games(self, user_id) -> Set[OfferId]:
        response = await self._http_client.get("{base_api}/atom/users/{user_id}/privacySettings/FAVORITEGAMES".format(
            base_api=self._get_origin_host(),
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

    # Doesn't exist in EA Desktop, meant to disappear soon.
    async def get_hidden_games(self, user_id) -> Set[OfferId]:
        response = await self._http_client.get("{base_api}/atom/users/{user_id}/privacySettings/HIDDENGAMES".format(
            base_api=self._get_origin_host(),
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
