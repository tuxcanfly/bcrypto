#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>

#include "common.h"
#include "ecdh.h"
#include "random/random.h"

static Nan::Persistent<v8::FunctionTemplate> ecdh_constructor;

BECDH::BECDH() {
  ctx = NULL;
}

BECDH::~BECDH() {
  if (ctx != NULL) {
    ecdh_context_destroy(ctx);
    ctx = NULL;
  }
}

void
BECDH::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BECDH::New);

  ecdh_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ECDH").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "_size", BECDH::Size);
  Nan::SetPrototypeMethod(tpl, "_bits", BECDH::Bits);
  Nan::SetPrototypeMethod(tpl, "privateKeyGenerate", BECDH::PrivateKeyGenerate);
  Nan::SetPrototypeMethod(tpl, "privateKeyVerify", BECDH::PrivateKeyVerify);
  Nan::SetPrototypeMethod(tpl, "publicKeyCreate", BECDH::PublicKeyCreate);
  Nan::SetPrototypeMethod(tpl, "publicKeyConvert", BECDH::PublicKeyConvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromUniform", BECDH::PublicKeyFromUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyToUniform", BECDH::PublicKeyToUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromHash", BECDH::PublicKeyFromHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyToHash", BECDH::PublicKeyToHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyVerify", BECDH::PublicKeyVerify);
  Nan::SetPrototypeMethod(tpl, "publicKeyIsSmall", BECDH::PublicKeyIsSmall);
  Nan::SetPrototypeMethod(tpl, "publicKeyHasTorsion", BECDH::PublicKeyHasTorsion);
  Nan::SetPrototypeMethod(tpl, "derive", BECDH::Derive);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(ecdh_constructor);

  Nan::Set(target, Nan::New("ECDH").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BECDH::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create ECDH instance.");

  if (info.Length() < 1)
    return Nan::ThrowError("ECDH() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  BECDH *ec = new BECDH();

  ec->ctx = ecdh_context_create(name);

  if (ec->ctx == NULL)
    return Nan::ThrowTypeError("Curve not available.");

  ec->scalar_size = ecdh_scalar_size(ec->ctx);
  ec->scalar_bits = ecdh_scalar_bits(ec->ctx);
  ec->field_size = ecdh_field_size(ec->ctx);
  ec->field_bits = ecdh_field_bits(ec->ctx);

  ec->Wrap(info.This());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BECDH::Size) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->field_size));
}

NAN_METHOD(BECDH::Bits) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->field_bits));
}

NAN_METHOD(BECDH::PrivateKeyGenerate) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  uint8_t out[ECDH_MAX_PRIV_SIZE];
  uint8_t entropy[32];

  if (!bcrypto_random(entropy, 32))
    return Nan::ThrowError("Could not generate entropy.");

  ecdh_privkey_generate(ec->ctx, out, entropy);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDH::PrivateKeyVerify) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  size_t key_len = node::Buffer::Length(kbuf);
  int result = key_len == ec->scalar_size;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDH::PublicKeyCreate) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t key_len = node::Buffer::Length(kbuf);
  uint8_t out[ECDH_MAX_PUB_SIZE];

  if (key_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid private key size.");

  ecdh_pubkey_create(ec->ctx, out, key);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BECDH::PublicKeyConvert) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdh.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  int sign = (int)Nan::To<bool>(info[1]).FromJust();
  uint8_t out[EDDSA_MAX_PUB_SIZE];
  size_t out_len = ec->field_size + ((ec->field_bits & 7) == 0);

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!ecdh_pubkey_convert(ec->ctx, out, pub, sign))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDH::PublicKeyFromUniform) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.publicKeyFromUniform() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);
  uint8_t out[ECDH_MAX_PUB_SIZE];

  if (data_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid field element size.");

  ecdh_pubkey_from_uniform(ec->ctx, out, data);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BECDH::PublicKeyToUniform) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdh.publicKeyToUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  unsigned int hint = (unsigned int)Nan::To<uint32_t>(info[1]).FromJust();
  uint8_t out[ECDH_MAX_FIELD_SIZE];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!ecdh_pubkey_to_uniform(ec->ctx, out, pub, hint))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BECDH::PublicKeyFromHash) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.publicKeyFromHash() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (info.Length() > 1 && !info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);
  int pake = 0;
  uint8_t out[ECDH_MAX_PUB_SIZE];

  if (info.Length() > 1)
    pake = (int)Nan::To<bool>(info[1]).FromJust();

  if (data_len != ec->field_size * 2)
    return Nan::ThrowRangeError("Invalid hash size.");

  if (!ecdh_pubkey_from_hash(ec->ctx, out, data, pake))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BECDH::PublicKeyToHash) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.publicKeyToHash() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t entropy[32];
  uint8_t out[ECDH_MAX_FIELD_SIZE * 2];

  if (!bcrypto_random(entropy, 32))
    return Nan::ThrowError("Could not generate entropy.");

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!ecdh_pubkey_to_hash(ec->ctx, out, pub, entropy))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size * 2).ToLocalChecked());
}

NAN_METHOD(BECDH::PublicKeyVerify) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->field_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdh_pubkey_verify(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDH::PublicKeyIsSmall) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.publicKeyIsSmall() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->field_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdh_pubkey_is_small(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDH::PublicKeyHasTorsion) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdh.publicKeyHasTorsion() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->field_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdh_pubkey_has_torsion(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDH::Derive) {
  BECDH *ec = ObjectWrap::Unwrap<BECDH>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdh.derive() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t key_len = node::Buffer::Length(sbuf);
  uint8_t out[ECDH_MAX_PUB_SIZE];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (key_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid private key size.");

  if (!ecdh_derive(ec->ctx, out, pub, key))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}