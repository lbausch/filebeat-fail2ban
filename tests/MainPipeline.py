import unittest
import BaseTestCase


class MainPipeline(BaseTestCase.BaseTestCase):
    pipeline_file = '../module/fail2ban/main/ingest/pipeline.json'

    def test_failing_pipeline(self):
        message = 'foo'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            'message': message,
            'error': {
                'message': 'Provided Grok expressions do not match field value: [foo]'
            }
        })

    def test_pipeline_found(self):
        message = '2025-07-14 13:03:14,963 fail2ban.filter         [100911]: INFO    [sshd] Found 123.123.123.123 - 2025-07-14 13:03:14'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-14T13:03:14.963Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.filter',
                'pid': 100911,
                'log_level': 'INFO',
                'jail': 'sshd',
                'message': 'found',
                'ip': '123.123.123.123',
                'event_timestamp': '2025-07-14 13:03:14',
            },
        })


    def test_pipeline_ignore(self):
        message = '2025-07-15 16:18:39,861 fail2ban.filter         [3833724]: INFO    [sshd] Ignore 123.123.123.123 by ip'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-15T16:18:39.861Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.filter',
                'pid': 3833724,
                'log_level': 'INFO',
                'jail': 'sshd',
                'message': 'ignore',
                'ip': '123.123.123.123',
            },
        })

    def test_pipeline_ban(self):
        message = '2025-07-14 13:22:07,454 fail2ban.actions        [100911]: NOTICE  [sshd] Ban 123.123.123.123'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-14T13:22:07.454Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.actions',
                'pid': 100911,
                'log_level': 'NOTICE',
                'jail': 'sshd',
                'message': 'ban',
                'ip': '123.123.123.123',
            },
        })

    def test_pipeline_increase(self):
        message = '2025-07-15 11:33:41,514 fail2ban.observer       [100911]: NOTICE  [sshd] Increase Ban 123.123.123.123 (2 # 2w 6d -> 2025-08-04 11:33:40)'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-15T11:33:41.514Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.observer',
                'pid': 100911,
                'log_level': 'NOTICE',
                'jail': 'sshd',
                'message': 'increase_ban',
                'ip': '123.123.123.123',
                'count': 2,
                'duration': '2w 6d',
                'expiry': '2025-08-04 11:33:40',
            },
        })

    def test_pipeline_unban(self):
        message = '2025-07-15 03:05:47,193 fail2ban.actions        [100911]: NOTICE  [sshd] Unban 123.123.123.123'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-15T03:05:47.193Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.actions',
                'pid': 100911,
                'log_level': 'NOTICE',
                'jail': 'sshd',
                'message': 'unban',
                'ip': '123.123.123.123',
            },
        })


if __name__ == '__main__':
    unittest.main()
