#!/user/bin/python

import sys
import argparse
import json
from report import JIRA


class OperateJIRA(JIRA):
    def __init__(self):
        super(OperateJIRA, self).__init__()

    def addComment(self, args):
        return self.addcomment(args.jira_id, args.comment)

    def renameFilter(self, args):
        return self.renamefilter(args.filter_id, args.new_name)

    def Summary(self, args):
        if args.getsummary:
            sys.stdout.write(self.getsummary(args.jira_id))
        else:
            return self.setsummary(args.jira_id, args.summary)

    def setStatus(self, args):
        return self.setstatus(args.jira_id, args.new_status)

    def queryjiraIDbyjql(self, args):
        jql = {'jql': "'TC Template' ~ {0} AND parent in ({1})".format(
            args.jira_id, args.parent_id)}
        sys.stdout.write(str(self.getjiraIDbyjql(jql)))


def setup_cmdline_parser():
    jira = OperateJIRA()
    parser = argparse.ArgumentParser(description='Operate JIRA API')
    subparsers = parser.add_subparsers()
    # create the parser for the comment
    parser_comment = subparsers.add_parser('comment')
    parser_comment.add_argument('-i', '--jira_id', type=str, required=True)
    parser_comment.add_argument('-c', '--comment', type=str, required=True)
    parser_comment.set_defaults(func=jira.addComment)

    # create the parser for the filter
    parser_filter = subparsers.add_parser('filter')
    parser_filter.add_argument('-i', '--filter_id', type=str, required=True)
    parser_filter.add_argument('-n', '--new_name', type=str, required=True)
    parser_filter.set_defaults(func=jira.renameFilter)

    # create the parser for the summary
    parser_summary = subparsers.add_parser('summary')
    parser_summary.add_argument('-i', '--jira_id', type=str, required=True)
    parser_summary.add_argument('-s', '--summary', type=str, required=False, default=False)
    parser_summary.add_argument('-g', '--getsummary', action='store_true', default=False)
    parser_summary.set_defaults(func=jira.Summary)

    # create the parser for the status
    parser_status = subparsers.add_parser('status')
    parser_status.add_argument('-i', '--jira_id', type=str, required=True)
    parser_status.add_argument('-s', '--new_status', type=str, required=True,
        help='Transitions name reference 1. Pass 2. Fail 3. Run Again \
        4. Reset Status 5. Set to Open 6. Start Test 7. Pending 8. Will Not Run \
        9. Not Supported 10. Blocked 11. Clear Counts 12. Set Version Tested')
    parser_status.set_defaults(func=jira.setStatus)

    # create the parser for the get original jiraID
    parser_query = subparsers.add_parser('query')
    parser_query.add_argument('-i', '--jira_id', type=str, required=True)
    parser_query.add_argument('-p', '--parent_id', type=str, required=True)
    parser_query.set_defaults(func=jira.queryjiraIDbyjql)

    args = parser.parse_args()
    rc = args.func(args)

if __name__ == "__main__":
    setup_cmdline_parser()
aaaaaaaaaaaaaaaaaaaaa
