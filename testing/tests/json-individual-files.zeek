# Test the basic JSON exporter's ability to write each log's schema to a
# separate file.
#
# @TEST-REQUIRES: type -p jq
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-test.json
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-prettify-json btest-diff zeek-second.json

@load ./testlog
@load logschema/export/json

redef Log::Schema::JSON::filename = "zeek-{log}.json";

module Second;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## An address.
		a: addr &log;
	};
}

event zeek_init() &priority=-1
	{
	Log::create_stream(Second::LOG, [$columns=Second::Info, $path="second"]);
	}
