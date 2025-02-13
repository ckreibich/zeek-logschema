module Log::Schema;

export {
	type Field: record {
		name: string;
		zeektype: string;
		script: string;
		is_optional: bool;
		docstring: string &optional;
		package: string &optional;
	};

	type Log: record {
		name: string;
		zeektype: string;
		fields: table[string] of Field;
	};

	type SchemaInfo: record {
		zeek_version: string &default = zeek_version();
	};

	global field_hook: hook(id: Log::ID, field: Field);
	global log_hook: hook(id: Log::ID, log: Log);
	global export_hook: hook(info: SchemaInfo, logs: table[Log::ID] of Log);
}

global logs: table[Log::ID] of Log;

event analyze()
	{
	for ( id, stream in Log::active_streams )
		{
		local zeektype = fmt("%s", stream$columns);
		local fields: table[string] of Field = table() &ordered;
		local name: string;

		if ( stream?$path )
			name = stream$path;
		else
			{
			# For the unusual case where we have not path, we make
			# one up from the record type's qualified name (without
			# the last part, which is usually "Info") and hope it
			# makes sense.
			local parts = split_string(zeektype, /::/);
			name = to_lower(join_string_vec(parts[0:-1], ""));
			}

		local rfields_table = record_fields(stream$columns);
		local rfields = record_type_to_vector(zeektype);

		for ( _, fieldname in rfields )
			{
			# We care only about fields that Zeek will log:
			if ( ! rfields_table[fieldname]$log )
				next;

			local field = Field(
			    $name = fieldname,
			    $zeektype = rfields_table[fieldname]$type_name,
			    $script = get_record_field_declaring_script(zeektype + "$" + fieldname),
			    $is_optional = rfields_table[fieldname]$optional);

			local docstring = get_record_field_comments(zeektype + "$" + fieldname);
			if ( |docstring| > 0 )
				field$docstring = docstring;

			if ( starts_with(field$script, "site/packages/") )
				field$package = split_string(field$script, /\//)[2];

			if ( hook field_hook(id, field) )
				fields[fieldname] = field;
			}

		local log = Log($name = name, $zeektype = zeektype, $fields = fields);

		if ( hook log_hook(id, log) )
			logs[id] = log;
		}

	hook export_hook(SchemaInfo(), logs);
	}

event zeek_init()
	{
	# Ensure log stream analysis runs after zeek_init handlers:
	schedule 0 sec { analyze() };
	}
