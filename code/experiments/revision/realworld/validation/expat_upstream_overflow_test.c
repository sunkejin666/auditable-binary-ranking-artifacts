/* Independent, API-level reproduction of Expat's upstream CVE-2022-23852
 * regression test.  It intentionally does not write the returned buffer: the
 * oracle is the contract-level response to the crafted size request. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *XML_Parser;
typedef XML_Parser (*parser_create_fn)(const char *encoding);
typedef int (*parse_fn)(XML_Parser parser, const char *s, int len, int isFinal);
typedef void *(*get_buffer_fn)(XML_Parser parser, int len);
typedef int (*get_error_fn)(XML_Parser parser);
typedef void (*parser_free_fn)(XML_Parser parser);

static void *must_symbol(void *handle, const char *name) {
  void *symbol = dlsym(handle, name);
  const char *error = dlerror();
  if (error != NULL || symbol == NULL) {
    fprintf(stderr, "dlsym(%s): %s\n", name, error ? error : "missing");
    exit(2);
  }
  return symbol;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s /absolute/path/to/libexpat.so\n", argv[0]);
    return 2;
  }
  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  parser_create_fn parser_create = (parser_create_fn)must_symbol(handle, "XML_ParserCreate");
  parse_fn parse = (parse_fn)must_symbol(handle, "XML_Parse");
  get_buffer_fn get_buffer = (get_buffer_fn)must_symbol(handle, "XML_GetBuffer");
  get_error_fn get_error = (get_error_fn)must_symbol(handle, "XML_GetErrorCode");
  parser_free_fn parser_free = (parser_free_fn)must_symbol(handle, "XML_ParserFree");

  XML_Parser parser = parser_create(NULL);
  if (parser == NULL) {
    fprintf(stderr, "XML_ParserCreate returned NULL\n");
    dlclose(handle);
    return 3;
  }
  const char text[] = "\n";
  int parsed = parse(parser, text, 1, 0);
  int request = INT_MAX - 1 + 1; /* upstream expectedKeepValue is strlen("\n") */
  void *buffer = get_buffer(parser, request);
  int error = get_error(parser);
  printf("{\"parsed\":%d,\"request\":%d,\"buffer_returned\":%s,\"error\":%d,\"writes_performed\":0}\n",
         parsed, request, buffer ? "true" : "false", error);
  parser_free(parser);
  dlclose(handle);
  return 0;
}
