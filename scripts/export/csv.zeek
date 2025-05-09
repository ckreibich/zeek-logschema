module Log::Schema::CSV;

@load ../main

export {
	type Field: record {
		log: string; ##< Name of the log, e.g. "conn"
		field: string; ##< Name of the field, e.g "uid"
		_type: string; ##< Zeek type of the field (e.g. "string", "addr", "bool")
		record_type: string;  ##< Record type containing this field (e.g. "Conn::Info", "conn_id").
		script: string;  ##< Script that defines the field, relative to the scripts folder (e.g. "base/init-bare.zeek").
		is_optional: bool;  ##< Whether the field is optional.
		_default: any &optional; ##< Default value of the field, if defined.
		docstring: string &optional;  ##< If available, the docstring for the field.
		package: string &optional;  ##< If part of a Zeek package, the package's name sans owner ("hello-world", not "zeek/hello-world").
	};

	type Export: record {
		zeek_version: string &default = zeek_version();
		logs: table[string] of vector of Field &ordered;
	};

	## The CSV field separator.
	const separator = "," &redef;

	## String to use for an unset &optional field.
	const unset_field = "-" &redef;

	## Whether to include a header line explaining the fields.
	const add_header = T &redef;

	## A file name to write each log's schema to. When this is empty or "-",
	## the export writes all schemas to stdout, in alphabetical order, with
	## one line per schema. For supported substitutions, see
	## Log::Schema::create_schema_filename().
	const filename_template = "zeek-logschema.csv";
}

redef record Log::Schema::Info += {
	csv_export: Export &optional;
};

hook Log::Schema::schema_hook(info: Log::Schema::Info)
	{
	local ex: Export = Export($zeek_version = info$zeek_version);
	local csv_field: Field;

	for ( _, log in info$logs )
		{
		ex$logs[log$name] = vector();
		for ( _, field in log$fields )
			{
			csv_field = Field(
			    $log=log$name,
			    $field=field$name,
			    $_type=field$_type,
			    $record_type=field$record_type,
			    $script=field$script,
			    $is_optional=field$is_optional);

			if ( field?$_default )
				csv_field$_default = field$_default;
			if ( field?$docstring )
				csv_field$docstring = field$docstring;
			if ( field?$package )
				csv_field$package = field$package;

			ex$logs[log$name] += csv_field;
			}
		}

	info$csv_export = ex;
	}

hook Log::Schema::write_hook(info: Log::Schema::Info)
	{
	local hdl: file;
	local filename: string;
	local s: vector of string;

	hdl = open(Log::Schema::create_schema_filename(filename_template, info));

	if ( add_header )
		{
		s = vector();

		for ( _, rfield in Log::Schema::get_record_fields("Log::Schema::CSV::Field", F) )
			s[|s|] = lstrip(rfield$name, "_");

		write_file(hdl, join_string_vec(s, separator));
		write_file(hdl, "\n");
		}

	for ( _, fields in info$csv_export$logs )
		{
		for ( _, field in fields )
			{
			s = vector();
			s[|s|] = field$log;
			s[|s|] = field$field;
			s[|s|] = field$_type;
			s[|s|] = field$record_type;
			s[|s|] = field$script;
			s[|s|] = to_json(field$is_optional);

			# The default value is of type "any", which is tricky to deal with here.
			s[|s|] = field?$_default ? to_json(field$_default) : unset_field;

			# Also use JSON for the docstring, since it conveniently
			# escapes newlines so the result renders single-line.
			s[|s|] = field?$docstring ? to_json(field$docstring) : unset_field;

			s[|s|] = field?$package ? field$package : unset_field;

			write_file(hdl, join_string_vec(s, separator));
			write_file(hdl, "\n");
			}
		}

	close(hdl);
	}
