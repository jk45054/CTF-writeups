// c2 ctor




// c2 handshake

  //bn_1337 = RhpNewFast(&BigInteger_mt); // 133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337

  // bn_rand_size_0x10 = pos_new_rand_bigint(128);
  // FpPoint_new = (c2->FpPoint->vtable->Multiply_with_BigInt)(c2->FpPoint, bn_rand_size_0x10);
  // FpPoint_norm = (FpPoint_new->vtable->Normalize)(FpPoint_new);

  // AffX = (FpPoint_norm->vtable->get_AffineXCoord)(FpPoint_norm);
  // bn_new_x = (AffX->vtable->ReturnToStringMethod)(AffX);
  // bn_1337_xor_bn_new_x = BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger__Xor(bn_new_x, bn_1337);
  // BigInteger::ToByteArray(bn_1337_xor_bn_new_x, 1, &v51 + 8);
  // c2_socket_send(c2_network_stream, &bn_new_x_size);// first send, size 48

  // AffY = (FpPoint_norm->vtable->get_AffineYCoord)(FpPoint_norm);
  // bn_new_y = (AffY->vtable->ReturnToStringMethod)(AffY);
  // bn_1337_xor_bn_new_y = BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger__Xor(bn_new_y, bn_1337);// 0?
  // BigInteger::ToByteArray(bn_1337_xor_bn_new_y, 1, &v51 + 8);
  // c2_socket_send(c2_network_stream, &bn_new_x_size);// second send, size 48

  // c2_socket_receive(c2_network_stream, &v51 + 8);
  // BC_BigInt_from_Bytes(recv_bn_x, 1, byte_array_size_0x30, 0, 0x30u, 1);
  // bn_1337_xor_bn_recv_x = BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger__Xor(recv_bn_x, bn_1337);

  // c2_socket_receive(c2_network_stream, &v51 + 8);// second receive, 48 bytes
  // BC_BigInt_from_Bytes(recv_bn_y, 1, byte_array_size_0x30, 0, 0x30u, 1);
  // bn_1337_xor_bn_recv_y = BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger__Xor(recv_bn_y, bn_1337);

  // Fp_serv = (c2->FpCurve->vtable->ValidatePoint)(c2->FpCurve, bn_1337_xor_bn_recv_x, bn_1337_xor_bn_recv_y);
  // Fp_serv_mult = (Fp_serv->vtable->Multiply_with_BigInt)(Fp_serv, bn_rand_size_0x10);
  // Fp_serv_mult_norm = (Fp_serv_mult->vtable->Normalize)(Fp_serv_mult);

  // serv_AffX = (Fp_serv_mult_norm->vtable->get_AffineXCoord)(Fp_serv_mult_norm);
  // serv_AffX_str = (serv_AffX->vtable->ReturnToStringMethod)(serv_AffX);
  // AffX_bytes_sha512 = System_Security_Cryptography_SHA512__HashData(byte_array_size_0x30);

  // ChaCha = RhpNewFast(&Org_BouncyCastle_Crypto_Engines_ChaChaEngine_mt);
  // something_with_uint_arrays(ChaCha, unk_140158AF8);
  // key_param = RhpNewFast(&Org_BouncyCastle_Crypto_Parameters_KeyParameter_mt);
  // RhpAssignRefAVLocation(key_param + 8, *AffX_hash_value);
  // chacha20 key = first 32 bytes of SHA512 of serv_AffX_str as bytes
  // iv_param = RhpNewFast(&Org_BouncyCastle_Crypto_Parameters_ParametersWithIV_mt);
  // RhpAssignRefAVLocation(iv_param + 16, *AffX_hash_value);
  // chacha20 iv = last 8 bytes of SHA512 of serv_AffX_str as bytes

  // decr_c2_msg = c2_fetch_and_decrypt_message(); // this likely decrypts something?
  // str_verify = decrypt_string(verify);          // verify
  // if ( !String__Equals_0(decr_c2_msg, str_verify) )// 1st check
  // return c2_send_encrypted(verify);



// c2 traffic decryption from pcap
// once we're able to decrypt verify message, we should be able to decrypt the rest

// each message is null terminated, as c2 recv enc loop reads 1 byte per while iteration, decr, breaks on null

