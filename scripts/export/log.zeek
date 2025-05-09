module Log::Schema::Log;

@load ../main

export {
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	type Field: record {
		log: string; ##< Name of the log, e.g. "conn"
		field: string; ##< Name of the field, e.g "uid"
		_type: string; ##< Zeek type of the field (e.g. "string", "addr", "bool")
		record_type: string;  ##< Record type containing this field (e.g. "Conn::Info", "conn_id").
		script: string;  ##< Script that defines the field, relative to the scripts folder (e.g. "base/init-bare.zeek").
		is_optional: bool;  ##< Whether the field is optional.
		_default: string &optional; ##< Default value of the field, if defined. Stringified since "any" and logging do not get along.
		docstring: string &optional;  ##< If available, the docstring for the field.
		package: string &optional;  ##< If part of a Zeek package, the package's name sans owner ("hello-world", not "zeek/hello-world").
	} &log;

	type Export: record {
		zeek_version: string &default = zeek_version();
		logs: table[string] of vector of Field &ordered;
	};

	## Event that can be handled to access the Field
	## record as it is sent on to the logging framework.
	global log_field: event(rec: Field);
}

global field_name_map: table[string] of string = table(
	["_type"] = "type",
	["_default"] = "default",
);

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
				csv_field$_default = cat(field$_default);
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
	for ( _, fields in info$csv_export$logs )
		for ( _, field in fields )
			Log::write(LOG, field);
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Field, $ev=log_field, $path="logschema", $policy=log_policy]);
	}
