# Test the Avro export. This writes per-log schema data by default.
#
# @TEST-REQUIRES: type -p jq
# @TEST-EXEC: zeek -b %INPUT >stdout 2>stderr
# @TEST-EXEC: btest-diff stdout
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test-log.avsc

@load ./testlog
@load logschema/export/avro
