"""Demo capture (Inspector) - load ONE embedded secret key, sign it N times, save
the traces. Same working Inspector capture as falcon_capture.py.
Then:  python falcon_demo.py <OUT path>
"""
import os

import serial
import riscure.inspector
from riscure.inspector import ManualInputTraceSetSink

PORT, BAUD = "COM6", 115200
N = 50
OUT = "C:/Users/mervkara/Inspector/data/demo/demo_v2.trs"
SET_KEY, SIGN = bytes([0x9B]), bytes([0x9C])
SIG_SIZE, MSG_SIZE = 666, 16
SAMPLE_RATE_MHZ, NUM_SAMPLES = 1000, 10000    # match the profile window (leak is at sample ~1070)
MEAS_CH, MEAS_RANGE_V = "Channel A", 0.2
TRIG_CH, TRIG_LEVEL_V = "External", 1
F0 = 2

# ---- one real Falcon-512 secret key, EMBEDDED (f[0]=2, f[1]=0) ----
PK = bytes.fromhex(
    "0927a8eb27ea1cf6577dafe4181131a0f6f77577a68e87ddd4a27809ab4e4a57096f1578126c4e145d84ca771cdaa2059e89b032e18991906b988eb38690cfc32684c320bd119752198870fe57829f79b0f667cb4d21901b2b4558886a5649126748055d7acf58982d0db1a98ebbec6ab06b4d2b51af4ff1b976c4aa58d0ef2189738809dc4d49c156a93ea96710e9d5b75061d8bc821d03170c0688860e32d229374d7a10610862fb202ce586e923b02b34f860d1655d6734d260f26f3b0fd68ac8e18bb028815ee5e71f4591cd172a5b95605834fb049123de0a44bba26e4337133171abd35945133d454b3cab339a2e1467be8ede7156623b08cc1f4f5cd1baf3946c39c2e9a1549823876147260c1f7613892955a8db0c33b67679fc5116bf29e258c8d3d03940a381578d9f9cf61901fd1a5f23bae9c0e7a83e14607d4276ac3250f4429af14e356904839094c8469a7cb70a1d66d6a1558a3488063d9edccee9e96a3c1535a98871dc2704d2f834496515ac963160902dd546f2c71473d53c71099648752ae0690a4e27070032b8e456fa601de95ec126f239cf4fa3ee3d0ac4eabdabbe4c65a8209d889d8da12517b69f556c059cc7262eb95c58fc81cd1949ddd6766ab18fe0a628e35b1384fc49e6998ea59ed1e7da4f88944582504bb981d85fc5238798c657402114c166ef860834d4168b20d3be1520b3a65dbf81692b424bc1eb594e5a2658d4f8bf2ad754bbe00c25de6d68af43224014f8872ca2daa0ddb4512f9eacb1fc1ad6deaf7064444b94e096404c95233b96068b408ae4090d841a4ce83d059648f4760af7784ed36289c881d7ca67d363da0021136051bbc55dba99926f62e431f10158d9bfa2f58a979afea705ba63da6101380d52e835a3bc8b7d6380740a449fd295ab3817df53d4cce5a5e5309e7eff2ac6d89a52394d68c3591e66d2ebc19c5fde039a8f3126886ab91d4857909f4b6142d0dbe84646937a9a72d24b5d11b53c002d81c2a74efb5aaf47a3a1c8933b851787a752c8d5168a7952ccf547150dd24bdd12e71009ef3354fc5689d9e8b4cc50009e888c74a407a6e006a10024aaa08144fe0b8c7c1ba1a298667575a997194e7e0a88d94428b65a9c40e1f79ac71d5184257e23dc6a0072327c10be2ad1dddb14d3aa6c6915193123773bedc9c62a404708b42255b5e6b177c233caa882783a256b9263169e6e08016620e6229a65d817608fe52b2c666bab24dc7f227ca92908c6")
SK = bytes.fromhex(
    "59080fba13f082f8307513d03a0090ff001041001e82201f3bec61450c3f3e0040c2183fc223dfffff70fef42d821bc1c6fbd18307c0fc08817deba146fc110127ee0107f0fc07ee0807efbf183fff180fc203cf7ae82ef8f3c041187f3d17f20313cfc3006f84f46e4303f105088fc5efff7508227cfbcf05f07104006081f41ffe000087e8313ff450381fc005f090800400c10caf7eff907e18107f101ec214310200304513f0be1fff05dfd0c10bf000044dc20c303f07afc703afbff7b00107fffef45ffffc007fec5f3efb6e400c2143108fbf07df051fff7f1c6044f3effcf41000e85f85fc00c500007f18110217f046ebeec4fc603e185fc40f8fc6181009ef608010600108103c0bfeffe00004042200005efd140f40f3e07de7edbdf780bd080f800c3085f011ba004181180f7b07c00117707b0cc0fbfb913f0440ffec20ffefb07d101e40fc1000ec3ebeff8245fc4003f3c041f03ffe07c1c8fc1000002fff0800840c4f41e880fcefb102185e0a07afc01bc03d0fc08317c04218504203dffc07c1430bd14310217f0fffc3fbf03eec5e81f3ffc1fc6e85ffe2bcf3f0800010bf03e0420fefbf0fafc203eec4f870c4f83fba1820fe041f7d040139fc3f7e0050c4e40f02f3afc2182fc203c07d0bd0bc0001790c1ec2fc108013ef86ef6101106dc60841c0f05f84047f8027e17bf3d001fc4f7f13cf0203ff45dc21fefc6ec40c217d1001ffec5000fc3f81fc3fc503ffffffef810fff8203ef83284f3ef81044043dbef43fc2f7f045248003fffe7e08023c107ffff42ec9143f83ec2ec30c8efbffd041f81dbee81e46efd0c00fbf3d043f3e0bef04ec3fc5141088287f86f41039fc3f80f4417a185ffe041041042139dc0fc0103f7c1bffff0b9ffbf8004107f001f031040bb23feff2c2efe0400000c8206ebee0634c006f47ec3049002f4317e101081ec313e146181f02f82f7a13f0421ba0ba181ffe100000ffe03ff7fd86efefbdfc217af3fe832fbfc0142fbfec4101f4303e1830bff3e081084e83ffee03fbfebeeff07e004efbefe0001c3079f3f03d0fe1bef1f7111f1a11df171b01e825ded9fed809d5ebf4ff0304dee2c73ef3ebfcfe230201ded5161a05e9e203eaeee4d8eee2e4081317ff07420c1019fbfbfd23f8b3ef0e2c1e04eadef3ee0df703f3eff90936fdefe80e26d11b11d40a010d190b0e2002f12afc0dfe0c12d900f3e6030401043408050602e63f02faef2bfc21e307dbfe12cc17f4e203da001e341df4f5d511013603d500280dfa3de6e019f201ebf412f321d61b08d71eecf9ddfcfde5e31612fc0fe7cd15ee2ce42bee04dbdd1de1cf2d19fdfc00d50b140c112af90f0706e726221ed9f0fefb1afae0fa0f0b2114e5f9f6f72811cfdbdaf22c0ef8ece2121a2dd6e9e9fde60929f61cf73b02e8ed09ef290ef905fe11f2fce0e4090eff44f3d8061522f7030ed9ede60eeaeaff0af1defb00d22a14f811092e27ee101af4d2c0fff9ff10f8ead3fccad709e8f402de19f70201191711eafceff4ddf9da0e1d0e04e4f851f9f109d200172010e7202ae5fee0f0fa1a0a2038d30518f8e112cdfb13251dee2c15ef02e9f132fef916f70b2ae8f114231bd7e3f8f41b260b02060a08f0fb0b02e01f320ff602480001fc05eff0ef0107f8f8f4130ce9ffe3d119fac92b14f014ffc0e9cbfae9dd03180e24e6f3fdefec1303d6fbe62004df20dd24022519e4fd3424190bcfc90aecdfe711d51c03060bd90513f22dce121db43343310fefe2bdcc021f04e41e0322")
print("SECRET KEY  ->  f[0]=+2, f[1]=+0")
print("  decoded f (int8) = 02 00 fe fa 04 ff 02 02 fe 03 ...   <- f[0]=02, f[1]=00")

ser = serial.Serial(PORT, BAUD, timeout=5.0)
with riscure.inspector.connect() as ins:
    print("Inspector connected")
    scopes = list(ins.get_connected_oscilloscopes())
    pico = next((s for s in scopes if "3000" in s["name"]), scopes[0])
    scope = ins.open_scope_device(pico)
    scope.scope_settings.number_of_samples = NUM_SAMPLES
    scope.scope_settings.time_per_sample = 1 / (SAMPLE_RATE_MHZ * 1_000_000)
    scope.channel_settings[MEAS_CH].enabled = True
    scope.channel_settings[MEAS_CH].range = MEAS_RANGE_V
    scope.trigger_settings.trigger_channel_name = TRIG_CH
    scope.trigger_settings.trigger_level = TRIG_LEVEL_V
    scope.calibrate()
    print(f"{NUM_SAMPLES} samples @ {SAMPLE_RATE_MHZ} MHz | {MEAS_CH} | trigger {TRIG_CH} @ {TRIG_LEVEL_V} V")

    ser.reset_input_buffer(); ser.write(SET_KEY + PK + SK)
    if ser.read(1) != bytes([0]):
        raise RuntimeError("set-key not acked")

    source = ins.create_scope_source(scope)
    sink = ManualInputTraceSetSink(ins, source.trace_meta_data,
                                   os.path.join(ins.settings.trace_set_path, OUT)).run()
    print(f"Collecting {N} traces of the secret key -> {OUT}")
    for i in range(N):
        scope.arm()
        ser.write(SIGN + os.urandom(MSG_SIZE))
        if ser.read(1) != bytes([0]) or len(ser.read(SIG_SIZE)) != SIG_SIZE:
            raise RuntimeError(f"sign failed ({i})")
        with source.get() as m:
            for tr in m.get_traces(MEAS_CH):
                tr.parameters["f0_class"] = bytes([F0 + 10])     # label = true f[0] + 10 (0..20)
                tr.parameters["f0"] = bytes([F0 & 0xFF])         # true f[0], signed int8
                tr.parameters["sk"] = SK                          # full encoded secret key
                sink.put(tr)
        print(f"  {i+1}/{N}", flush=True)
    ser.close()
print("done. now run:   python falcon_test.py", OUT)
