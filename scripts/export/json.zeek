module Log::Schema::JSON;

@load ../main

export {
	## A JSON-suitable, Zeek-specific representation of the schema data.
	type Export: record {
		zeek_version: string &default = zeek_version();
		logs: table[string] of vector of Log::Schema::Field &ordered;
	};
}

redef record Log::Schema::Info += {
	json_export: Export &optional;
};

hook Log::Schema::schema_hook(info: Log::Schema::Info)
	{
	local ex: Export = Export($zeek_version = info$zeek_version);

	for ( _, log in info$logs )
		{
		ex$logs[log$name] = vector();
		for ( _, field in log$fields )
			ex$logs[log$name] += field;
		}

	info$json_export = ex;
	}

hook Log::Schema::write_hook(info: Log::Schema::Info)
	{
	print to_json(info$json_export);
	}
