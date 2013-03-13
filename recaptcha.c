#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

#define RECAPTCHA_VERIFY_SERVER "http://www.google.com/recaptcha/api/verify"
#define RECAPTCHA_PUBLIC_KEY "xxx"
#define RECAPTCHA_PRIVATE_KEY "yyy"


struct recaptcha {
   int code;
   char ref[50];
};


// recaptcha return "true" or "false" on first line
size_t re_callback(char * data, size_t size, size_t nmemb, void * user)
{
   size_t len = size * nmemb;
   struct recaptcha *recaptcha = (struct recaptcha*) user;

   if (!recaptcha)
      return ;
   recaptcha->code = (strncmp(data, "true", 4) == 0 ? 1 : 0);
   memset(recaptcha->ref, '\0', sizeof(char));
   if (recaptcha->code == 0) {
      strncpy(recaptcha->ref, strchr(data, '\n') + 1, 49);
   }

   return len;
}

static struct recaptcha recaptcha_response(const char *privatekey, const char *remoteip,
   const char *challenge, const char *response)
{

   struct recaptcha recaptcha = {0, "Request Failed"};

   if (*challenge == '\0' ||  *response == '\0') {
      return recaptcha;
   }


   CURL *curl = curl_easy_init();
   CURLcode res;
   struct curl_httppost *formpost = NULL;
   struct curl_httppost *lastptr = NULL;

   if(!curl)
      return recaptcha;

   curl_formadd(&formpost, &lastptr,
      CURLFORM_COPYNAME, "privatekey",
      CURLFORM_COPYCONTENTS, privatekey, CURLFORM_END);
   curl_formadd(&formpost, &lastptr,
      CURLFORM_COPYNAME, "remoteip",
      CURLFORM_COPYCONTENTS, remoteip, CURLFORM_END);
   curl_formadd(&formpost, &lastptr,
      CURLFORM_COPYNAME, "challenge",
      CURLFORM_COPYCONTENTS, challenge, CURLFORM_END);
   curl_formadd(&formpost, &lastptr,
      CURLFORM_COPYNAME, "response",
      CURLFORM_COPYCONTENTS, response, CURLFORM_END);

   curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
   curl_easy_setopt(curl, CURLOPT_URL, RECAPTCHA_VERIFY_SERVER);
   curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, re_callback);
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, &recaptcha);

   res = curl_easy_perform(curl);
   curl_easy_cleanup(curl);
   curl_formfree(formpost);
   //if (res != CURLE_OK)
   return recaptcha;
}