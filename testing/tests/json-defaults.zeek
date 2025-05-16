# Test the basic JSON export of schema information.
#
# @TEST-REQUIRES: type -p jq
# @TEST-EXEC: zeek -b %INPUT >stdout 2>stderr
# @TEST-EXEC: btest-diff stdout
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-logschema.json

@load ./testlog
@load logschema/export/json
