import unittest

from scripts import check_upstream as monitor


class IssueFixture:
    def __init__(self):
        self.body = "old baseline"
        self.comments = []
        self.fail_patch = None
        self.fail_after_post = None
        self.patches = 0

    def request(self, suffix="", payload=None, method="GET"):
        if method == "PATCH":
            self.patches += 1
            if self.patches == self.fail_patch:
                raise OSError("PATCH failed")
            self.body = payload["body"]
        elif method == "POST":
            self.comments.append(payload)
            if len(self.comments) == self.fail_after_post:
                raise OSError("POST succeeded but response was lost")
        else:
            page = int(suffix.rsplit("=", 1)[1])
            return self.comments[(page - 1) * 100:page * 100]


class IssueOutboxTests(unittest.TestCase):
    def test_initial_patch_failure_does_not_publish_comments(self):
        issue = IssueFixture()
        issue.fail_patch = 1
        with self.assertRaises(OSError):
            monitor.publish_issue(issue.request, "new baseline", ["report"])
        self.assertEqual(issue.body, "old baseline")
        self.assertEqual(issue.comments, [])

    def test_ambiguous_post_failure_resumes_missing_pages_without_duplicates(self):
        issue = IssueFixture()
        issue.comments.extend({"body": f"previous comment {index}"} for index in range(100))
        issue.fail_after_post = 101
        with self.assertRaises(OSError):
            monitor.publish_issue(issue.request, "new baseline", ["first", "second"])
        self.assertEqual(monitor.read_outbox(issue.body), ("new baseline", ["first", "second"]))
        self.assertEqual(len(issue.comments), 101)
        monitor.deliver_outbox(issue.request, issue.body)
        self.assertEqual(issue.body, "new baseline")
        self.assertEqual([item["body"].splitlines()[-1] for item in issue.comments[100:]], ["first", "second"])

    def test_cleanup_patch_failure_resumes_without_reposting_delivered_comments(self):
        issue = IssueFixture()
        issue.fail_patch = 2
        with self.assertRaises(OSError):
            monitor.publish_issue(issue.request, "new baseline", ["report"])
        self.assertEqual(len(issue.comments), 1)
        monitor.deliver_outbox(issue.request, issue.body)
        self.assertEqual(issue.body, "new baseline")
        self.assertEqual(len(issue.comments), 1)
