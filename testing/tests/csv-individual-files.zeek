# Test the CSV export. This writes to a single output file by default.
#
# @TEST-EXEC: zeek -b %INPUT >stdout 2>stderr
# @TEST-EXEC: btest-diff stdout
# @TEST-EXEC: btest-diff stderr
# @TEST-EXEC: btest-diff zeek-test.csv
# @TEST-EXEC: btest-diff zeek-second.csv

@load ./testlog
@load logschema/export/csv

redef Log::Schema::CSV::filename = "zeek-{log}.csv";

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
