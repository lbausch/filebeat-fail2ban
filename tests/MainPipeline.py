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
                'action': 'found',
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
                'action': 'ignore',
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
                'action': 'ban',
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
                'action': 'increase ban',
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
                'action': 'unban',
                'ip': '123.123.123.123',
            },
        })

    def test_pipeline_already_banned(self):
        message = '2025-07-15 16:52:34,236 fail2ban.actions        [3837823]: WARNING [sshd] 123.123.123.123 already banned'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-15T16:52:34.236Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.actions',
                'pid': 3837823,
                'log_level': 'WARNING',
                'jail': 'sshd',
                'action': 'already banned',
                'ip': '123.123.123.123',
            },
        })

    def test_pipeline_unban_failure(self):
        message = "2025-07-15 17:44:35,623 fail2ban.actions        [3837823]: ERROR   Failed to execute unban jail 'sshd' action 'nftables' info 'ActionInfo({'ip': '123.123.123.123', 'family': 'inet4', 'fid': <function Actions.ActionInfo.<lambda> at 0x7fdf9cb4d080>, 'raw-ticket': <function Actions.ActionInfo.<lambda> at 0x7fdf9cb4d800>})': Error unbanning 123.123.123.123"

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-15T17:44:35.623Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.actions',
                'pid': 3837823,
                'log_level': 'ERROR',
                'message': "Failed to execute unban jail 'sshd' action 'nftables' info 'ActionInfo({'ip': '123.123.123.123', 'family': 'inet4', 'fid': <function Actions.ActionInfo.<lambda> at 0x7fdf9cb4d080>, 'raw-ticket': <function Actions.ActionInfo.<lambda> at 0x7fdf9cb4d800>})': Error unbanning 123.123.123.123",
            },
        })

    def test_pipeline_error_with_threadid(self):
        message = "2025-07-15 19:22:37,314 fail2ban.utils          [3837823]: ERROR   7fdf96be4630 -- stderr: 'Error: Could not process rule: No such file or directory'"

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-15T19:22:37.314Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.utils',
                'pid': 3837823,
                'log_level': 'ERROR',
                'threadid': '7fdf96be4630',
                'message': "stderr: 'Error: Could not process rule: No such file or directory'",
            },
        })

    def test_pipeline_error_command_action(self):
        message = '2025-07-15 15:47:39,155 fail2ban.CommandAction  [3837823]: ERROR   Invariant check failed. Unban is impossible.'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-15T15:47:39.155Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.CommandAction',
                'pid': 3837823,
                'log_level': 'ERROR',
                'message': 'Invariant check failed. Unban is impossible.',
            },
        })

    def test_pipeline_rollover(self):
        message = '2025-07-13 06:25:02,320 fail2ban.server         [1342]: INFO    rollover performed on /var/log/fail2ban.log'

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-13T06:25:02.320Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.server',
                'pid': 1342,
                'log_level': 'INFO',
                'message': 'rollover performed on /var/log/fail2ban.log',
            },
        })

    def test_pipeline_decoding_error(self):
        message = "2025-07-13 20:21:03,713 fail2ban.filter         [588]: WARNING Error decoding line from '/var/log/auth.log' with 'UTF-8'."

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-13T20:21:03.713Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.filter',
                'pid': 588,
                'log_level': 'WARNING',
                'message': "Error decoding line from '/var/log/auth.log' with 'UTF-8'.",
            },
        })

    def test_pipeline_reban(self):
        message = "2025-07-16 02:21:17,285 fail2ban.actions        [100911]: NOTICE  [sshd] Reban 123.123.123.123, action 'nftables'"

        response = self.request(message)
        source = self.source(response)

        self.assertSourceEquals(source, {
            '@timestamp': '2025-07-16T02:21:17.285Z',
            'fail2ban': {
                'message_raw': message,
                'module': 'fail2ban.actions',
                'pid': 100911,
                'log_level': 'NOTICE',
                'jail': 'sshd',
                'action': 'reban',
                'ip': '123.123.123.123',
            },
        })


if __name__ == '__main__':
    unittest.main()
