#ifndef _BCRYPTO_SALSA20_HH
#define _BCRYPTO_SALSA20_HH

#include <node.h>
#include <nan.h>

#include "salsa20/salsa20.h"

class BSalsa20 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BSalsa20();
  ~BSalsa20();

  bcrypto_salsa20_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Crypt);
  static NAN_METHOD(Destroy);
  static NAN_METHOD(Derive);
};
#endif
