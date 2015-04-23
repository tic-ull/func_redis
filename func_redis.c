/*
 * func_redis.c
 * 
 * Author : Sergio Medina Toledo <lumasepa@gmail.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Functions for interaction with Redis database
 *
 * \author Sergio Medina Toledo <lumasepa@gmail.com>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>extended</support_level>
 ***/


#include <asterisk.h>

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 1 $")


#include <asterisk/module.h>
#include <asterisk/channel.h>
#include <asterisk/pbx.h>
#include <asterisk/utils.h>
#include <asterisk/app.h>
#include <asterisk/cli.h>
#include <asterisk/config.h>

#ifndef AST_MODULE
#define AST_MODULE "func_redis"
#endif

#include <hiredis/hiredis.h>

/*** DOCUMENTATION
	<function name="REDIS" language="en_US">
		<synopsis>
			Read from or write to a Redis database.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will read from or write a value to the Redis database.  On a
			read, this function returns the corresponding value from the database, or blank
			if it does not exist.  Reading a database value will also set the variable
			REDIS_RESULT.  If you wish to find out if an entry exists, use the REDIS_EXISTS
			function.</para>
		</description>
		<see-also>
			<ref type="function">REDIS_DELETE</ref>
			<ref type="function">REDIS_EXISTS</ref>
		</see-also>
	</function>
	<function name="REDIS_EXISTS" language="en_US">
		<synopsis>
			Check to see if a key exists in the Redis database.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will check to see if a key exists in the Redis
			database. If it exists, the function will return <literal>1</literal>. If not,
			it will return <literal>0</literal>.  Checking for existence of a database key will
			also set the variable REDIS_RESULT to the key's value if it exists.</para>
		</description>
		<see-also>
			<ref type="function">REDIS</ref>
		</see-also>
	</function>
	<function name="REDIS_KEYS" language="en_US">
		<synopsis>
			Obtain a list of keys within the Redis database.
		</synopsis>
		<syntax>
			<parameter name="prefix" />
		</syntax>
		<description>
			<para>This function will return a comma-separated list of keys existing
			at the prefix specified within the Redis database.  If no argument is
			provided, then a list of key families will be returned.</para>
		</description>
	</function>
	<function name="REDIS_DELETE" language="en_US">
		<synopsis>
			Return a value from the database and delete it.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will retrieve a value from the Redis database
			and then remove that key from the database. <variable>REDIS_RESULT</variable>
			will be set to the key's value if it exists.</para>
		</description>
	</function>
 ***/

#define REDIS_CONF "redis.conf"
#define STR_CONF_SZ 128

AST_MUTEX_DEFINE_STATIC(redis_lock);

redisContext * redis = NULL;
redisReply * reply = NULL;


static char hostname[STR_CONF_SZ] = "";
static char dbname[STR_CONF_SZ] = "";
static int port = 6379;

static int load_config(int is_reload)
{
	struct ast_config *config;
	const char *s;
	struct ast_flags config_flags = { is_reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };

	config = ast_config_load(REDIS_CONF, config_flags);
	if (config == CONFIG_STATUS_FILEUNCHANGED) {
		return 0;
	}

	if (config == CONFIG_STATUS_FILEMISSING || config == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_WARNING, "Unable to load config %s\n", REDIS_CONF);
		return 0;
	}

	ast_mutex_lock(&redis_lock);

	if (redis) {
		redisFree(redis);
	}

	if (!(s = ast_variable_retrieve(config, "general", "hostname"))) {
		ast_log(LOG_WARNING,
				"Redis: No redis hostname.\n");
		hostname[0] = '\0';
	} else {
		ast_copy_string(hostname, s, sizeof(hostname));
	}

	if (!(s = ast_variable_retrieve(config, "general", "port"))) {
		ast_log(LOG_WARNING,
				"Redis: No Redis port found, using 6379 as default.\n");
		port = 6379;
	} else {
		port = atoi(s);
	}
	
	if (!(s = ast_variable_retrieve(config, "general", "dbname"))) {
		ast_log(LOG_WARNING,
				"Redis: No database name found, using 'asterisk' as default.\n");
		strcpy(dbname, "asterisk");
	} else {
		ast_copy_string(dbname, s, sizeof(dbname));
	}

	ast_config_destroy(config);

	struct timeval timeout = { 3, 500000 }; // 3.5 seconds
	redis = redisConnectWithTimeout(hostname, port, timeout);

	if (!redis) {
		ast_log(LOG_WARNING,
				"Redis: Couldn't establish connection.\n");
		return 0;
	}

	ast_verb(2, "Redis reloaded.\n");

	/* Done reloading. Release lock so others can now use driver. */
	ast_mutex_unlock(&redis_lock);

	return 1;
}



static int function_redis_read(struct ast_channel *chan, const char *cmd,
			    char *parse, char *buf, size_t len)
{
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(key);
	);

	buf[0] = '\0';

	if (ast_strlen_zero(parse)) {
		ast_log(LOG_WARNING, "REDIS requires one argument, REDIS(<key>)\n");
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, parse);

	if (args.argc != 1) {
		ast_log(LOG_WARNING, "REDIS requires one argument, REDIS(<key>)\n");
		return -1;
	}

	reply = redisCommand(redis,"GET %s", args.key);

	if (reply == NULL) {
		ast_debug(1, "REDIS: %s not found in database.\n", args.key);
	} else {
		strcpy(buf, reply->str);
		pbx_builtin_setvar_helper(chan, "REDIS_RESULT", buf);
	}

	freeReplyObject(reply);

	return 0;
}

static int function_redis_write(struct ast_channel *chan, const char *cmd, char *parse,
			     const char *value)
{
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(key);
	);

	if (ast_strlen_zero(parse)) {
		ast_log(LOG_WARNING, "REDIS requires one argument, REDIS(<key>)=<value>\n");
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, parse);

	if (args.argc != 1) {
		ast_log(LOG_WARNING, "REDIS requires one argument, REDIS(<key>)=<value>\n");
		return -1;
	}

	reply = redisCommand(redis,"SET %s %s", args.key, value);

	if (reply == NULL) {
		ast_log(LOG_WARNING, "REDIS: Error writing value to database.\n");
	}

	freeReplyObject(reply);

	return 0;
}

static struct ast_custom_function redis_function = {
	.name = "REDIS",
	.read = function_redis_read,
	.write = function_redis_write,
};

static int function_redis_exists(struct ast_channel *chan, const char *cmd,
			      char *parse, char *buf, size_t len)
{
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(key);
	);

	buf[0] = '\0';

	if (ast_strlen_zero(parse)) {
		ast_log(LOG_WARNING, "REDIS_EXISTS requires one argument, REDIS(<key>)\n");
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, parse);

	if (args.argc != 1) {
		ast_log(LOG_WARNING, "REDIS_EXISTS requires one argument, REDIS(<key>)\n");
		return -1;
	}


	reply = redisCommand(redis,"EXISTS %s", args.key);

	if (reply == NULL) {
		strcpy(buf, "0");
	} else {
		pbx_builtin_setvar_helper(chan, "REDIS_RESULT", buf);
		strcpy(buf, "1");
	}

	return 0;
}

static struct ast_custom_function redis_exists_function = {
	.name = "REDIS_EXISTS",
	.read = function_redis_exists,
	.read_max = 2,
};

static int function_redis_keys(struct ast_channel *chan, const char *cmd, char *parse, struct ast_str **result, ssize_t maxlen)
{

        if (ast_strlen_zero(parse)) {
                ast_log(LOG_WARNING, "REDIS_KEYS requires no argument, REDIS_KEYS()\n");
                return -1;
        }
        
        ast_log(LOG_ERROR, "REDIS_KEYS Not implemented yet\n");
        
	return 0;
}

static struct ast_custom_function redis_keys_function = {
	.name = "REDIS_KEYS",
	.read2 = function_redis_keys,
};

static int function_redis_delete(struct ast_channel *chan, const char *cmd,
			      char *parse, char *buf, size_t len)
{
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(key);
	);

	buf[0] = '\0';

	if (ast_strlen_zero(parse)) {
		ast_log(LOG_WARNING, "REDIS_DELETE requires an argument, REDIS_DELETE(<key>)\n");
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, parse);

	if (args.argc != 1) {
		ast_log(LOG_WARNING, "REDIS_DELETE requires one argument, REDIS_DELETE(<key>)\n");
		return -1;
	}

	reply = redisCommand(redis,"DEL %s", args.key);

	if (reply == NULL) {
		ast_debug(1, "REDIS_DELETE: %s not found in database.\n", args.key);
	}

	freeReplyObject(reply);

	return 0;
}

/*!
 * \brief Wrapper to execute REDIS_DELETE from a write operation. Allows execution
 * even if live_dangerously is disabled.
 */
static int function_redis_delete_write(struct ast_channel *chan, const char *cmd, char *parse,
	const char *value)
{
	/* Throwaway to hold the result from the read */
	char buf[128];
	return function_redis_delete(chan, cmd, parse, buf, sizeof(buf));
}

static struct ast_custom_function redis_delete_function = {
	.name = "REDIS_DELETE",
	.read = function_redis_delete,
	.write = function_redis_delete_write,
};

static char *handle_cli_redis_del(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int res;

	switch (cmd) {
	case CLI_INIT:
		e->command = "redis del";
		e->usage =
			"Usage: redis del <key>\n"
			"       Deletes an entry in the Redis database for a given key.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3)
		return CLI_SHOWUSAGE;
	reply = redisCommand(redis,"DEL %s", a->argv[2]);
	
	if (reply == NULL) {
		ast_cli(a->fd, "Redis database entry does not exist.\n");
	} else {
		ast_cli(a->fd, "Redis database entry removed.\n");
	}
	freeReplyObject(reply);
	return CLI_SUCCESS;
}

static char *handle_cli_redis_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "redis show";
		e->usage =
			"Usage: redis show\n"
			"   OR: redis show key\n"
			"       Shows Redis database contents, optionally restricted\n"
			"       to a key.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	
	if (a->argc == 3) {
		/* key */
		reply = redisCommand(redis,"KEYS %s", a->argv[2]);
	} else if (a->argc == 2) {
		/* show all */
		reply = redisCommand(redis,"KEYS *");
	} else {
		return CLI_SHOWUSAGE;
	}
	
	int i = 0;
	redisReply * get_reply;

	for(i = 0; i < reply->elements; i++){
		get_reply = redisCommand(redis,"GET %s", reply->element[i]->str);
	    if(get_reply != NULL)
	    {
			ast_cli(a->fd, "%-50s: %-25s\n", reply->element[i]->str, get_reply->str);
	    }
		freeReplyObject(get_reply);
	}

	ast_cli(a->fd, "%d results found.\n", (int)reply->elements);
	freeReplyObject(reply);

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_func_redis[] = {
	AST_CLI_DEFINE(handle_cli_redis_show, "Get all Redis values or by pattern in key"),
	AST_CLI_DEFINE(handle_cli_redis_del, "Delete a key and value in Redis"),
};

static int unload_module(void)
{
	int res = 0;
	reply = redisCommand(redis, "BGSAVE");
	freeReplyObject(reply);
	redisFree(redis);
	
	ast_cli_unregister_multiple(cli_func_redis, ARRAY_LEN(cli_func_redis));
	res |= ast_custom_function_unregister(&redis_function);
	res |= ast_custom_function_unregister(&redis_exists_function);
	res |= ast_custom_function_unregister(&redis_delete_function);
	res |= ast_custom_function_unregister(&redis_keys_function);

	return res;
}

static int load_module(void)
{
	if(!load_config(0))
		return AST_MODULE_LOAD_DECLINE;
	int res = 0;
	
	ast_cli_register_multiple(cli_func_redis, ARRAY_LEN(cli_func_redis));
	res |= ast_custom_function_register_escalating(&redis_function, AST_CFE_BOTH);
	res |= ast_custom_function_register(&redis_exists_function);
	res |= ast_custom_function_register_escalating(&redis_delete_function, AST_CFE_READ);
	res |= ast_custom_function_register(&redis_keys_function);

	return res;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Redis related dialplan functions");


