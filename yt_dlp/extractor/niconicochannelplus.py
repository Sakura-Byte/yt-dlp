import base64
import functools
import hashlib
import json
import os
import time
import urllib.parse
import uuid

from ..networking.exceptions import HTTPError
from .common import InfoExtractor
from ..utils import (
    ExtractorError,
    OnDemandPagedList,
    filter_dict,
    int_or_none,
    parse_qs,
    str_or_none,
    traverse_obj,
    unified_timestamp,
    urlencode_postdata,
    url_or_none,
)


class NiconicoChannelPlusBaseIE(InfoExtractor):
    _NETRC_MACHINE = 'niconicochannelplus'
    _WEBPAGE_BASE_URL = 'https://nicochannel.jp'
    _AUTH0_REDIRECT_URI = f'{_WEBPAGE_BASE_URL}/login/login-redirect'
    _AUTH0_SCOPE = 'openid profile email offline_access read:user_email_addresses read:user_nicknames read:user_memberships'
    _USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'
    _AUTH0_CLIENT_ID = None
    _AUTH0_DOMAIN = None
    _API_ACCESS_TOKEN = None
    _API_ACCESS_TOKEN_EXPIRY = 0
    _API_REFRESH_TOKEN = None
    _LOGIN_HINT = ('Use --username token --password ACCESS_TOKEN where ACCESS_TOKEN '
                   'is the Auth0 "access_token" from your browser storage or the '
                   'https://auth.nicochannel.jp/oauth/token response')
    _REFRESH_HINT = 'or else use a "refresh_token" with --username refresh --password REFRESH_TOKEN'

    def _call_api(self, path, item_id, **kwargs):
        return self._download_json(
            f'https://api.nicochannel.jp/fc/{path}', video_id=item_id, **kwargs)

    @staticmethod
    def _parse_jwt_payload(token):
        if not token or token.count('.') < 2:
            return None
        try:
            payload = token.split('.')[1]
            payload += '=' * (-len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload.encode()))
        except Exception:
            return None

    @classmethod
    def _set_api_access_token(cls, value):
        NiconicoChannelPlusBaseIE._API_ACCESS_TOKEN = value
        NiconicoChannelPlusBaseIE._API_ACCESS_TOKEN_EXPIRY = traverse_obj(
            NiconicoChannelPlusBaseIE._parse_jwt_payload(value), ('exp', {int})) or 0

    @property
    def _api_access_token_is_expired(self):
        return NiconicoChannelPlusBaseIE._API_ACCESS_TOKEN_EXPIRY - 30 <= int(time.time())

    def _cache_auth0_tokens(self):
        self.cache.store(self._NETRC_MACHINE, 'tokens', {
            'access_token': NiconicoChannelPlusBaseIE._API_ACCESS_TOKEN,
            'refresh_token': NiconicoChannelPlusBaseIE._API_REFRESH_TOKEN,
        })

    def _load_cached_auth0_tokens(self):
        if self.get_param('cachedir') is False or self._API_ACCESS_TOKEN or self._API_REFRESH_TOKEN:
            return
        cached_tokens = self.cache.load(self._NETRC_MACHINE, 'tokens', default={})
        self._set_api_access_token(cached_tokens.get('access_token'))
        NiconicoChannelPlusBaseIE._API_REFRESH_TOKEN = cached_tokens.get('refresh_token')

    def _get_auth0_client_info(self):
        if NiconicoChannelPlusBaseIE._AUTH0_CLIENT_ID and NiconicoChannelPlusBaseIE._AUTH0_DOMAIN:
            return NiconicoChannelPlusBaseIE._AUTH0_DOMAIN, NiconicoChannelPlusBaseIE._AUTH0_CLIENT_ID

        login_data = self._call_api(
            'fanclub_sites/1/login', item_id='fanclub_sites/1/login',
            headers={'fc_use_device': 'null'},
            note='Fetching login info', errnote='Unable to fetch login info',
        )
        NiconicoChannelPlusBaseIE._AUTH0_CLIENT_ID = traverse_obj(
            login_data, ('data', 'fanclub_site', 'auth0_web_client_id', {str}))
        NiconicoChannelPlusBaseIE._AUTH0_DOMAIN = traverse_obj(
            login_data, ('data', 'fanclub_site', 'fanclub_group', 'auth0_domain', {str}))
        if not NiconicoChannelPlusBaseIE._AUTH0_CLIENT_ID or not NiconicoChannelPlusBaseIE._AUTH0_DOMAIN:
            raise ExtractorError('Unable to determine NicoChannel Plus Auth0 client info')
        return NiconicoChannelPlusBaseIE._AUTH0_DOMAIN, NiconicoChannelPlusBaseIE._AUTH0_CLIENT_ID

    def _fetch_new_auth0_tokens(self, *, invalidate=False):
        self._load_cached_auth0_tokens()

        if invalidate:
            self.report_warning('Access token has been invalidated')
            self._set_api_access_token(None)

        if self._API_ACCESS_TOKEN and not self._api_access_token_is_expired:
            return self._API_ACCESS_TOKEN

        if not self._API_REFRESH_TOKEN:
            self._set_api_access_token(None)
            self._cache_auth0_tokens()
            return None

        auth0_domain, client_id = self._get_auth0_client_info()

        try:
            response = self._download_json(
                f'https://{auth0_domain}/oauth/token', None,
                'Refreshing API token', 'Unable to refresh API token',
                data=urlencode_postdata({
                    'client_id': client_id,
                    'grant_type': 'refresh_token',
                    'refresh_token': self._API_REFRESH_TOKEN,
                }), headers={
                    'Accept': 'application/json, text/plain, */*',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': self._WEBPAGE_BASE_URL,
                    'Referer': f'{self._WEBPAGE_BASE_URL}/',
                    'User-Agent': self._USER_AGENT,
                })
        except ExtractorError as e:
            if isinstance(e.cause, HTTPError) and e.cause.status in (400, 401, 403):
                self._set_api_access_token(None)
                NiconicoChannelPlusBaseIE._API_REFRESH_TOKEN = None
                self._cache_auth0_tokens()
                raise ExtractorError('Your NicoChannel Plus tokens have been invalidated', expected=True)
            raise

        self._set_api_access_token(response.get('access_token'))
        if refresh_token := traverse_obj(response, ('refresh_token', {str})):
            NiconicoChannelPlusBaseIE._API_REFRESH_TOKEN = refresh_token
        self._cache_auth0_tokens()
        return self._API_ACCESS_TOKEN

    def _perform_auth0_password_login(self, username, password):
        auth0_domain, client_id = self._get_auth0_client_info()

        code_verifier = uuid.uuid4().hex + uuid.uuid4().hex + uuid.uuid4().hex
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')
        auth0_client = base64.urlsafe_b64encode(
            json.dumps({'name': 'auth0-spa-js', 'version': '2.8.0'}).encode()).decode().rstrip('=')

        login_page_handle = self._request_webpage(
            f'https://{auth0_domain}/authorize', None, 'Requesting login page',
            headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'User-Agent': self._USER_AGENT,
            }, query={
                'client_id': client_id,
                'scope': self._AUTH0_SCOPE,
                'redirect_uri': self._AUTH0_REDIRECT_URI,
                'audience': 'api.nicochannel.jp',
                'prompt': 'login',
                'response_type': 'code',
                'response_mode': 'query',
                'state': base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip('='),
                'nonce': base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip('='),
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'auth0Client': auth0_client,
            })
        login_url = login_page_handle.url
        login_state = traverse_obj(parse_qs(login_url), ('state', 0, {str}))
        if not login_state:
            raise ExtractorError('Unable to initialize Auth0 login session')

        redirect_url = self._request_webpage(
            login_url, None, 'Logging in',
            data=urlencode_postdata({
                'state': login_state,
                'username': username,
                'password': password,
            }), headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': f'https://{auth0_domain}',
                'Referer': login_url,
                'User-Agent': self._USER_AGENT,
            }, expected_status=404).url

        authorization_code = traverse_obj(parse_qs(redirect_url), ('code', 0, {str}))
        if not authorization_code:
            auth_error = traverse_obj(parse_qs(redirect_url), ('error', 0, {str}))
            if auth_error:
                raise ExtractorError(f'Unable to log in: {auth_error}', expected=True)
            raise ExtractorError(
                'Unable to log in with username/password. '
                'The site may require additional verification such as CAPTCHA or MFA', expected=True)

        response = self._download_json(
            f'https://{auth0_domain}/oauth/token', None,
            'Downloading API token', 'Unable to download API token',
            data=urlencode_postdata({
                'client_id': client_id,
                'code_verifier': code_verifier,
                'grant_type': 'authorization_code',
                'code': authorization_code,
                'redirect_uri': self._AUTH0_REDIRECT_URI,
            }), headers={
                'Accept': 'application/json, text/plain, */*',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': self._WEBPAGE_BASE_URL,
                'Referer': f'{self._WEBPAGE_BASE_URL}/',
                'User-Agent': self._USER_AGENT,
            })

        self._set_api_access_token(response.get('access_token'))
        NiconicoChannelPlusBaseIE._API_REFRESH_TOKEN = traverse_obj(response, ('refresh_token', {str}))
        if not self._API_ACCESS_TOKEN or not self._API_REFRESH_TOKEN:
            raise ExtractorError('Unable to complete NicoChannel Plus login')
        self._cache_auth0_tokens()

    def _get_auth0_api_headers(self):
        self._load_cached_auth0_tokens()
        if self._API_ACCESS_TOKEN and self._api_access_token_is_expired:
            if self._API_REFRESH_TOKEN:
                self._fetch_new_auth0_tokens()
            else:
                self._set_api_access_token(None)
                self._cache_auth0_tokens()
        elif not self._API_ACCESS_TOKEN and self._API_REFRESH_TOKEN:
            self._fetch_new_auth0_tokens()
        if self._API_ACCESS_TOKEN:
            return {'Authorization': f'Bearer {self._API_ACCESS_TOKEN}'}
        return {}

    @staticmethod
    def _is_auth0_session_error(error):
        return isinstance(error.cause, HTTPError) and error.cause.status in (401, 403)

    def _call_api_with_auth(self, path, item_id, *, headers=None, **kwargs):
        auth_headers = self._get_auth0_api_headers()
        if not auth_headers:
            raise ExtractorError(
                'NicoChannel Plus now requires an Auth0 API token that is stored outside cookies. '
                f'{self._LOGIN_HINT}, {self._REFRESH_HINT}', expected=True)

        request_headers = {
            **(headers or {}),
            **auth_headers,
        }
        try:
            return self._call_api(path, item_id=item_id, headers=request_headers, **kwargs)
        except ExtractorError as e:
            if not self._API_REFRESH_TOKEN or not self._is_auth0_session_error(e):
                raise
            self._fetch_new_auth0_tokens(invalidate=True)
            return self._call_api(
                path, item_id=item_id, headers={
                    **(headers or {}),
                    **self._get_auth0_api_headers(),
                }, **kwargs)

    def _find_fanclub_site_id(self, channel_name):
        domain_query = urllib.parse.quote(f'{self._WEBPAGE_BASE_URL}/{channel_name}')
        fanclub_json = self._call_api(
            f'content_providers/channel_domain?current_site_domain={domain_query}',
            item_id=f'channels/{channel_name}',
            headers={'fc_use_device': 'null'},
            note='Fetching channel site ID', errnote='Unable to fetch channel site ID',
        )
        fanclub_id = traverse_obj(fanclub_json, ('data', 'content_providers', 'fanclub_site', 'id'))
        if not fanclub_id:
            raise ExtractorError(f'Channel {channel_name} does not exist', expected=True)
        return fanclub_id

    def _get_channel_base_info(self, fanclub_site_id):
        return traverse_obj(self._call_api(
            f'fanclub_sites/{fanclub_site_id}/page_base_info', item_id=f'fanclub_sites/{fanclub_site_id}',
            headers={'fc_use_device': 'null', 'fc_site_id': str(fanclub_site_id)},
            note='Fetching channel base info', errnote='Unable to fetch channel base info', fatal=False,
        ), ('data', 'fanclub_site', {dict})) or {}

    def _get_channel_user_info(self, fanclub_site_id):
        return traverse_obj(self._call_api(
            f'fanclub_sites/{fanclub_site_id}/user_info', item_id=f'fanclub_sites/{fanclub_site_id}',
            headers={'fc_use_device': 'null', 'fc_site_id': str(fanclub_site_id), 'Content-Type': 'application/json'},
            note='Fetching channel user info', errnote='Unable to fetch channel user info', fatal=False,
            data=b'null',
        ), ('data', 'fanclub_site', {dict})) or {}

    def _perform_login(self, username, password):
        self._load_cached_auth0_tokens()
        if self._API_ACCESS_TOKEN and not self._api_access_token_is_expired:
            return

        self.report_login()

        if username == 'refresh':
            # Refresh tokens are rotated on use. When this extractor is initialized
            # again for playlist entries, prefer the newer cached/shared token.
            if self._API_REFRESH_TOKEN and self._API_REFRESH_TOKEN != password:
                try:
                    self._fetch_new_auth0_tokens()
                    return
                except ExtractorError:
                    pass
            NiconicoChannelPlusBaseIE._API_REFRESH_TOKEN = password
            self._set_api_access_token(None)
            self._fetch_new_auth0_tokens()
        elif username == 'token':
            if not traverse_obj(self._parse_jwt_payload(password), {dict}):
                raise ExtractorError(
                    f'The access token passed to yt-dlp is not valid. {self._LOGIN_HINT}', expected=True)
            self._set_api_access_token(password)
            self._cache_auth0_tokens()
        elif username == 'cache':
            self._load_cached_auth0_tokens()
            if self._API_REFRESH_TOKEN and (not self._API_ACCESS_TOKEN or self._api_access_token_is_expired):
                self._fetch_new_auth0_tokens()
        else:
            self._perform_auth0_password_login(username, password)

        if username in ('refresh', 'token') and self.get_param('cachedir') is not False:
            token_type = 'access' if username == 'token' else 'refresh'
            self.to_screen(
                f'Your {token_type} token has been cached to disk. '
                'To reuse cached tokens next time, pass --username cache along with any password')


class NiconicoChannelPlusIE(NiconicoChannelPlusBaseIE):
    IE_NAME = 'NiconicoChannelPlus'
    IE_DESC = 'ニコニコチャンネルプラス'
    _VALID_URL = r'https?://nicochannel\.jp/(?P<channel>[\w.-]+)/(?:video|live)/(?P<code>sm\w+)'

    def _get_live_status_and_session_id(self, content_code, data_json, fanclub_site_id):
        video_type = data_json.get('type')
        live_finished_at = data_json.get('live_finished_at')

        payload = {}
        if video_type == 'vod':
            if live_finished_at:
                live_status = 'was_live'
            else:
                live_status = 'not_live'
        elif video_type == 'live':
            if not data_json.get('live_started_at'):
                return 'is_upcoming', ''

            if not live_finished_at:
                live_status = 'is_live'
            else:
                live_status = 'was_live'
                payload = {'broadcast_type': 'dvr'}

                video_allow_dvr_flg = traverse_obj(data_json, ('video', 'allow_dvr_flg'))
                video_convert_to_vod_flg = traverse_obj(data_json, ('video', 'convert_to_vod_flg'))

                self.write_debug(f'allow_dvr_flg = {video_allow_dvr_flg}, convert_to_vod_flg = {video_convert_to_vod_flg}.')

                if not (video_allow_dvr_flg and video_convert_to_vod_flg):
                    raise ExtractorError(
                        'Live was ended, there is no video for download.', video_id=content_code, expected=True)
        else:
            raise ExtractorError(f'Unknown type: {video_type}', video_id=content_code, expected=False)

        self.write_debug(f'{content_code}: video_type={video_type}, live_status={live_status}')

        session_request_data = b'{}' if not payload else json.dumps(payload).encode('ascii')
        session_request_headers = {
            'Content-Type': 'application/json',
            'fc_use_device': 'null',
            'origin': 'https://nicochannel.jp',
            'fc_site_id': str(fanclub_site_id),
        }
        try:
            session_id = self._call_api(
                f'video_pages/{content_code}/session_ids', item_id=f'{content_code}/session',
                data=session_request_data, headers=session_request_headers,
                note='Getting session id', errnote='Unable to get session id',
            )['data']['session_id']
        except ExtractorError as e:
            if not self._is_auth0_session_error(e):
                raise
            session_id = self._call_api_with_auth(
                f'video_pages/{content_code}/session_ids', item_id=f'{content_code}/session',
                data=session_request_data, headers=session_request_headers,
                note='Getting session id', errnote='Unable to get session id',
            )['data']['session_id']

        return live_status, session_id

    def _get_comments(self, content_code, comment_group_id):
        item_id = f'{content_code}/comments'

        if not comment_group_id:
            return None

        try:
            comment_access_token = self._call_api_with_auth(
                f'video_pages/{content_code}/comments_user_token', item_id,
                headers={'fc_use_device': 'null'},
                note='Getting comment token', errnote='Unable to get comment token',
            )['data']['access_token']
        except Exception:
            return None

        comment_list = self._download_json(
            'https://comm-api.sheeta.com/messages.history', video_id=item_id,
            note='Fetching comments', errnote='Unable to fetch comments',
            headers={'Content-Type': 'application/json'},
            query={
                'sort_direction': 'asc',
                'limit': int_or_none(self._configuration_arg('max_comments', [''])[0]) or 120,
            },
            data=json.dumps({
                'token': comment_access_token,
                'group_id': comment_group_id,
            }).encode('ascii'))

        for comment in traverse_obj(comment_list, ...):
            yield traverse_obj(comment, {
                'author': ('nickname', {str}),
                'author_id': ('sender_id', {str_or_none}),
                'id': ('id', {str}),
                'text': ('message', {str}),
                'timestamp': ('created_at', {unified_timestamp}),
            })

    def _real_extract(self, url):
        content_code, channel_id = self._match_valid_url(url).group('code', 'channel')
        fanclub_site_id = self._find_fanclub_site_id(channel_id)

        data_json = self._call_api(
            f'video_pages/{content_code}', item_id=content_code, headers={'fc_use_device': 'null', 'fc_site_id': str(fanclub_site_id)},
            note='Fetching video page info', errnote='Unable to fetch video page info',
        )['data']['video_page']

        live_status, session_id = self._get_live_status_and_session_id(content_code, data_json, fanclub_site_id)

        release_timestamp_str = data_json.get('live_scheduled_start_at')

        formats = []

        if live_status == 'is_upcoming':
            if release_timestamp_str:
                msg = f'This live event will begin at {release_timestamp_str} UTC'
            else:
                msg = 'This event has not started yet'
            self.raise_no_formats(msg, expected=True, video_id=content_code)
        else:
            formats = self._extract_m3u8_formats(
                # "authenticated_url" is a format string that contains "{session_id}".
                m3u8_url=data_json['video_stream']['authenticated_url'].format(session_id=session_id),
                video_id=content_code)

        return {
            'id': content_code,
            'formats': formats,
            '_format_sort_fields': ('tbr', 'vcodec', 'acodec'),'channel': self._get_channel_base_info(fanclub_site_id).get('fanclub_site_name'),
            'channel_id': channel_id,
            'channel_url': f'{self._WEBPAGE_BASE_URL}/{channel_id}',
            'age_limit': traverse_obj(self._get_channel_user_info(fanclub_site_id), ('content_provider', 'age_limit')),
            'live_status': live_status,
            'release_timestamp': unified_timestamp(release_timestamp_str),
            **traverse_obj(data_json, {
                'title': ('title', {str}),
                'thumbnail': ('thumbnail_url', {url_or_none}),
                'description': ('description', {str}),
                'timestamp': ('released_at', {unified_timestamp}),
                'duration': ('active_video_filename', 'length', {int_or_none}),
                'comment_count': ('video_aggregate_info', 'number_of_comments', {int_or_none}),
                'view_count': ('video_aggregate_info', 'total_views', {int_or_none}),
                'tags': ('video_tags', ..., 'tag', {str}),
            }),
            '__post_extractor': self.extract_comments(
                content_code=content_code,
                comment_group_id=traverse_obj(data_json, ('video_comment_setting', 'comment_group_id'))),
        }


class NiconicoChannelPlusChannelBaseIE(NiconicoChannelPlusBaseIE):
    _PAGE_SIZE = 12

    def _fetch_paged_channel_video_list(self, path, query, channel_name, item_id, page):
        site_id = path.split('/')[1]
        response = self._call_api(
            path, item_id, query={
                **query,
                'page': (page + 1),
                'per_page': self._PAGE_SIZE,
            },
            headers={'fc_use_device': 'null', 'fc_site_id': site_id},
            note=f'Getting channel info (page {page + 1})',
            errnote=f'Unable to get channel info (page {page + 1})')

        for content_code in traverse_obj(response, ('data', 'video_pages', 'list', ..., 'content_code')):
            # "video/{content_code}" works for both VOD and live, but "live/{content_code}" doesn't work for VOD
            yield self.url_result(
                f'{self._WEBPAGE_BASE_URL}/{channel_name}/video/{content_code}', NiconicoChannelPlusIE)


class NiconicoChannelPlusChannelVideosIE(NiconicoChannelPlusChannelBaseIE):
    IE_NAME = 'NiconicoChannelPlus:channel:videos'
    IE_DESC = 'ニコニコチャンネルプラス - チャンネル - 動画リスト. nicochannel.jp/channel/videos'
    _VALID_URL = r'https?://nicochannel\.jp/(?P<id>[a-z\d\._-]+)/videos(?:\?.*)?'

    def _real_extract(self, url):
        """
        API parameters:
            sort:
                -released_at         公開日が新しい順 (newest to oldest)
                 released_at         公開日が古い順 (oldest to newest)
                -number_of_vod_views 再生数が多い順 (most play count)
                 number_of_vod_views コメントが多い順 (most comments)
            vod_type (is "vodType" in "url"):
                0 すべて (all)
                1 会員限定 (members only)
                2 一部無料 (partially free)
                3 レンタル (rental)
                4 生放送アーカイブ (live archives)
                5 アップロード動画 (uploaded videos)
        """

        channel_id = self._match_id(url)
        fanclub_site_id = self._find_fanclub_site_id(channel_id)
        channel_name = self._get_channel_base_info(fanclub_site_id).get('fanclub_site_name')
        qs = parse_qs(url)
        return self.playlist_result(
            OnDemandPagedList(
                functools.partial(
                    self._fetch_paged_channel_video_list, f'fanclub_sites/{fanclub_site_id}/video_pages',
                    filter_dict({
                        'tag': traverse_obj(qs, ('tag', 0)),
                        'sort': traverse_obj(qs, ('sort', 0), default='-released_at'),
                        'vod_type': traverse_obj(qs, ('vodType', 0), default='0'),
                    }),
                    channel_id, f'{channel_id}/videos'),
                self._PAGE_SIZE),
            playlist_id=f'{channel_id}-videos', playlist_title=f'{channel_name}-videos')


class NiconicoChannelPlusChannelLivesIE(NiconicoChannelPlusChannelBaseIE):
    IE_NAME = 'NiconicoChannelPlus:channel:lives'
    IE_DESC = 'ニコニコチャンネルプラス - チャンネル - ライブリスト. nicochannel.jp/channel/lives'
    _VALID_URL = r'https?://nicochannel\.jp/(?P<id>[a-z\d\._-]+)/lives'

    def _real_extract(self, url):
        """
        API parameters:
            live_type:
                1 放送中 (on air)
                2 放送予定 (scheduled live streams, oldest to newest)
                3 過去の放送 - すべて (all ended live streams, newest to oldest)
                4 過去の放送 - 生放送アーカイブ (all archives for live streams, oldest to newest)
            We use "4" instead of "3" because some recently ended live streams could not be downloaded.
        """

        channel_id = self._match_id(url)
        fanclub_site_id = self._find_fanclub_site_id(channel_id)
        channel_name = self._get_channel_base_info(fanclub_site_id).get('fanclub_site_name')

        return self.playlist_result(
            OnDemandPagedList(
                functools.partial(
                    self._fetch_paged_channel_video_list, f'fanclub_sites/{fanclub_site_id}/live_pages',
                    {
                        'live_type': 4,
                    },
                    channel_id, f'{channel_id}/lives'),
                self._PAGE_SIZE),
            playlist_id=f'{channel_id}-lives', playlist_title=f'{channel_name}-lives')
