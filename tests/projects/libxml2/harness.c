#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

void ignore_error(void *ctx, const char *msg, ...) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int initialized = 0;
  if (!initialized)
  {
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, ignore_error);
    initialized = 1;
  }

  xmlDocPtr doc = xmlReadMemory(
      (const char *)data,
      (int)size,
      "noname.xml",
      NULL,
      XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NONET);

  if (doc)
  {
    xmlFreeDoc(doc);
  }

  return 0;
}