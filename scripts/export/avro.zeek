## Schema export for Apache Avro.
##
## For the spec, see: https://avro.apache.org/docs/1.11.1/specification/

module Log::Schema::Avro;

@load ../main

export {
	type Field: record {
		name: string;
		doc: string &optional;
		_type: string; # JSON export strips leading "_".

		# Not currently used but in spec:
		# _default: string &optional;
		# order: string &default = "ignore";
	};

	type Record: record {
		name: string;
		namespace: string &optional;
		doc: string &optional;

		# Not currently used but in spec:
		# aliases: vector of string &optional;

		fields: vector of Field;
	};

	# A more JSON-suitable representation of the schema info.
	type Export: record {
		logs: table[string] of Record &ordered;
	};

	# Each log's Avro record can have a namespace. The exporter uses the
	# following by default. Redef this to the empty string to omit.
	const namespace = "org.zeek.logs" &redef;
}

redef record Log::Schema::Info += {
	avro_export: Export &optional;
};

function map_type(typ: string): string
	{
	if ( /^(set|vector)/ in typ )
		return "array";
	if ( /^(count|int)/ in typ )
		return "long";
	if ( /^(port)/ in typ )
		return "int";
	if ( /^(double|interval)/ in typ )
		return "double";
	if ( /^(enum|string|addr|subnet|pattern)/ in typ )
		return "string";
	if ( /^(bool)/ in typ )
		return "boolean";
	if ( typ == "time" )
		return "string";

	Reporter::warning(fmt("Unexpected type string for Avro mapping: %s", typ));
	return typ;
	}

hook Log::Schema::schema_hook(info: Log::Schema::Info)
	{
	local ex: Export = Export();
	local r: Record;
	local f: Field;

	for ( _, log in info$logs )
		{
		r = Record($name = log$name);

		if ( |namespace| > 0 )
			r$namespace = namespace;

		for ( _, field in log$fields )
			{
			f = Field($name = field$name, $_type = map_type(field$typ));

			if ( field?$docstring )
				f$doc = field$docstring;

			r$fields += f;
			}

		ex$logs[log$name] = r;
		}

	info$avro_export = ex;
	}

hook Log::Schema::write_hook(info: Log::Schema::Info)
	{
	for ( _, rec in info$avro_export$logs )
		print to_json(rec);
	}
