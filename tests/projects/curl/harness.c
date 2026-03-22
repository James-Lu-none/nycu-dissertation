#include <curl/curl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int initialized = 0;
  if (!initialized) {
    curl_global_init(CURL_GLOBAL_ALL);
    initialized = 1;
  }

  CURL *curl = curl_easy_init();
  if (curl) {
    char *url = malloc(size + 1);
    if (!url) return 0;
    memcpy(url, data, size);
    url[size] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
    // Ignore output
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    // Disable SSL verification for fuzzing efficiency (if needed)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_perform(curl);

    free(url);
    curl_easy_cleanup(curl);
  }
  return 0;
}
