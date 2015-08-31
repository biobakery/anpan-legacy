import time
import zlib
from itertools import izip, tee

from anpan import password

big_pile_o_names = "0..SbssV 0.MThK8Mb6P 0.NbX 0.NenNbGQUfT 0.Nq4fZfa0tH 0.NvqXurAq 0.OXC4 0.OhjqPaf 0.P 0.PJs 0.PuDa 0.Q1CkheaB 0.Q6 0.Qtc8i 0.R5hV 0.S3FY 0.S6N 0.SjMQ8 0.TJYo 0.Ta6 0.TnveYqvNgA 0.TzHK8F1jDO 0.UDHZb6I9T 0.UNK 0.Uj3sq 0.Ureftpw 0.V5rk 0.VeVx5J 0.Vm4k 0.VyX 0.XJWQOcctK7 0.XTGW 0.Xn1.Z 0.Y5kXG1xZoI 0.YNv6H2p 0.Ye 0.YlZ 0.Z7 0.mLj 0.mysbaL9o 0.n2EWHFT8Yi 0.n3ie 0.nC6OOvweK 0.nHYw1 0.nJQ74yfe 0.nmkXSC 0.no5 0.o 0.o3V 0.oAtt 0.oE5imjF 0.oJZI 0.ojeDFwa 0.ol 0.p009d3VU33o 0.pAc 0.pY7EF 0.ppPGWhKX 0.psX4u. 0.psxo 0.pw3rN 0.pyiEY7axuf 0.q0h0D9T 0.q0myBebf 0.qOVNHX 0.qmMYV 0.r.BPj 0.r4S0i 0.rGshf 0.ryHdaIkk8Dc 0.s74 0.s9vCp 0.sTvRIq 0.sUc 0.su6P 0.sx 0.sy.y 0.t1G9 0.tHkjLv1hRC 0.tl6QRX 0.tlzPqyV4vT2 0.upHLpnk0iL 0.uuE 0.vSgpnf4wW 0.vURHCDQ 0.vv9O 0.w8di 0.wa5vF5G 0.wjRZx 0.x.O 0.x0IMxbpI 0.xAhNZ82maRY-di 0.xUTNf 0.xj1fTur 0.xvK 0.xyb 0.yF 0.yZw8Y 0.ykCUHX 0.ypf 0.ypfF 0.yt6B 0.z1L 0.zEP 0.zXrU1 0.zh 0MM550L 0MNYX6Q 0MUi8jcI 0MWIf07QhN00Y 0Mv2F 0N764U2 0N7Qh08 0N90N3F 0N93G 0NADK66 0NBirV 0NCFU11 0NGP872 0NGUi0 0NGUi0P1 0NGUi0P1eMGD208Z 0NGUi0P2 0NMrwy 0NN22VA 0NT1TB4 0NWYj08 0Nette0 0Nikki0 0Nitti 0Nooo0 0O09jNWP2QXJ40YZJV0 0O3O7ND 0O56047 0O7al102 0O7al209ZJVP80XZ 0O88FT4 0OA9Z06 0OL9M00 0OWin0820P020P800PX 0OZYoZL978 0Ogmo0P2 0Oo0oo 0Or0u 0Or1u 0OtrmnWR 0P00000 0P00001 0P00VOl 0P0R8R80100 0P1341Q 0P1ADE4207AdM080TY 0P1eMGD0302 0P1mOGd207inOP0308 0P28R8P0102 0P2IVIT30 0P2KA5l 0P2N06420 0P2NdOX0100nA 0P2OWil20 0P2UaO0 0P2VWll20 0P3oool 0P3oool0103oolH0P01D0 0P52B9V 0PB 0PETR 0PEXGCS 0PH6107alO01jNWX0Ogmo08Z 0PH6108 0PH610P2 0PO8GUY 0POgj 0PS 0PYcT08 0PjhR41x 0PlP70nw 0Q5KD3H 0Q6fv 0Q8B400L0QHF508J6QP25QHD0PX 0Q8B402PX 0Q92g7hP 0QFYJ10 0QHF508Z 0QHF50P2 0QJ5p1Ze 0QXJ60 0QXJ608J6QP28R8P208Z 0QXJ609BDU0020 0QXJ60P1nOWh206IVIP80TY 0QXJ60P28R8P0102 0QizBwO0 0Ques432 0QviSkS343 0R01g102 0R4400LYAE 0R6fw 0R7aw 0R8R80 0R8R808Z 0R8R8102XZ 0RACLE 0RA_ORA 0RE44CY 0RF696 0RHNE7Z 0RI0N5 0RI0N5-0ijoesi 0RITMOMI 0RPnpvnV 0RQ42GM 0RQPR9I 0RacKL 0S0QIDJ 0S2E0LA 0S4O30Y 0S4n10P1O 0SGOOD 0SI5JJ6 0SIRIS 0SKW39I 0SPICE0 0SZ0y3l1 0SZ1PZA 0Shizzle 0SutY300 0T08CSZ 0T3eH 0T3eb 0T53WYD 0T6VAZ2 0T71365 0T9708E 0TB2NFE 0TD4O87 0TFTDOO 0THSTREET 0THYRM6 0THzZst 0TI6A0 0TWIOR1 0Tg2X06IVIP2CL 0TieH 0TjeI 0TzYqFWF 0U0D0I02K1P1N0 0U423I 0U5079S 0U54P65 0U6V0R7 0U7Y9U6 0U812 0U9BD09bLW0P0Z 0U9BD0P2 0U9BD102PX 0UD0AJ4 0UD4Z35 0UIFE102 0URCT3V 0UYJF09 0Uebv 0Uecw 0UfNI0P2LM 0UiNG08 0UiNG09jNWP2NWYh00P2EUID309 0UuC1Gsz 0V464V5 0V4X409Q 0V6hd0 0V9RH0 0V9RH09jNWP2PX 0VIVI0 0VIVI0P1oOgl 0VIVI102PX 0VIVI4P1oOgl 0VIWHR1 0VL3c0080VL3c0P00001D0 0VL9V1F 0VSI6102E 0VUld 0VYZJ102PX 0Vfcw 0VgJX0P2ON 0W01M0 0W01S0P2Z05D20 0W6ZD0 0W824XQ 0WBJ702 0WD81T4 0WHJj0ol000090 0WPZUMX 0WUld 0WYjN0 0WZkS0 0WhiteFang0 0WinO09JFUP2EUID0U9BD09 0WjSM0P0000120 0WlKc0 0X00000TP3oool 0X0ED4E 0X1AXD3 0X5MM57E 0XE88R0 0XJ6Q0 0XJBB43 0XLOc0 0XLSd0 0XWZW0P2UO 0XlOb0 0XtVx 0Y01I0 0Y01J0 0Y027C1 0Y03oool00 0Y6ZD0 0Y8940 0YAT00P00000 0YB65J7 0YIC40 0YKOU0 0YL1Tems 0YM3JLH 0YPXT3H 0YTZE2up 0YVPXI7 0YYCJCX 0YZCD0 0YZJV0 0YZJV0P2PX 0YdQzMZ4 0Yhp0Tvs 0YjNW0 0YkOT0 0Z00D0 0Z5PvwKU 0Z98M25 0ZJKD0 0ZJVY0 0ZKST0 0ZKWT0 0ZKgX0ol000030 0ZPcnX17 0ZVX1D8 0ZYBOV3 0ZYuOv1A 0ZZZZ02XZ 0ZbAc 0ZcAd 0ZpAc 0ZpAd 0ZqUd 0_NATAN 0_ReggieJ 0_TUC_0 0_natsb 0_nposis21 0_odenko1 0_p0p 0_paladin 0_plated 0_rringg 0_scoles9826 0_shithot 0_spear47 0_talex 0_tthokaor 0_verif02 0_w_n_4_g_er 0_ympi91 0mkprq1y2gw 0mkt5q 0mla824ri 0mlcerervx 0mm15 0mmce5 0mmez 0mmy_13 0mn1g1rl1836 0mn1p0t3nt 0mnxto 0mo4 0moed6y 0monqspoc 0monte 0mor00000 0mpah 0mq0 0mqh 0mqy2037g0309 0mri110 0mriwac3 0mrnadkbg7 0mrogers 0mrv7ajyns 0mryyg5v5d 0mspz1fa1w 0mu0c 0mu6k45qmh661l0m0h41pofi65 0muen5s0 0mushin 0mv6joc3 0mvt7wyekko 0mws0n 0mxmsj1n 0my7lubg 0myyxph7i31 0n065nv0 0n0olub 0n2i6jvf 0n2kro 0n331f4dq 0n5dmhnl 0n64mp 0n6id 0n6o3 0n6vak 0n7b5q5lqrf 0n7r0ouh 0n7vh 0n8nl 0nDhnMc8 0nFhMdefib68 0nLine 0na2599wh0409 0nad 0nai0ftu 0nakcpcgd 0narch 0natfis1 0natfis7 0natfis9 0natfish 0nbekend 0nbf0d14n 0nbv 0ncemore 0nder1 0ndmember 0ne22 0ne4fun 0neb6ieyo 0nedring 0negativezero0 0ness 0nest0p 0nfyq6s7zn 0nh3ybYY 0nhm100 0ni0nb0Y 0niczwv 0nikki01 0nimda 0nioclei5 0nirevetS 0nj9vtMM 0nkayhh3q 0nktncg 0nl1ne 0nlin3r 0nlinev1per 0nluclwy 0nly4m3 0nlyOne4 0nnlav6p7sy 0no1to0 0noe580z 0nogarden0 0nomi0 0noway2 0nq2wupxf 0nq8346 0nqn2h 0ns3f 0nsCuBZA 0nslaught 0nsr4ypxz01 0nsxqd0m 0nt50 0nth3b4ll 0nu856vuus1 0nuVnYWX 0nudefree 0nvabkbo 0nvk9jpw 0nvlblzw 0nvq6jah3w 0nvxsm22t40 0nw2fzw 0nward_4eva 0nwmxdinq 0nwycjkm 0nx8p5 0ny2m7n16p 0nyzf12f 0nz34 0o0 0o0eedo 0o0eklq 0o0jk6i3zd 0o1asdy2".split()


def timeit(func, *args, **kwargs):
    prev = time.time()
    func(*args, **kwargs)
    after = time.time()
    return after-prev

def test__safe_str_cmp():
    assert password._safe_str_cmp("aaaaa", "aaaaa") == True
    assert password._safe_str_cmp("bbbaa", "aaaaa") == False
    early_equal = ("10000000000", "00000000000")
    late_equal = ("00000000001", "00000000000")

    def longcmp(a, b, n=10000):
        for i in xrange(n):
            password._safe_str_cmp(a, b)

    ratio = timeit(longcmp, *early_equal) / timeit(longcmp, *late_equal)
    assert 0.9 < ratio < 1.1


def test_compare():
    a, b = map(password.hash, ("foobaz", "quux"))
    assert password.compare(a, a) == True
    assert password.compare(a, b) == False

mean = lambda xs: sum(xs)/len(xs)

def compression_ratio(s):
    return len(zlib.compress(s)) / float(len(s))

def test_salt():
    assert len(password.salt()) == password.DEFAULT_SALT_LEN
    assert len(password.salt(8)) == 8

    salts = [password.salt() for _ in xrange(100)]
    assert mean(map(compression_ratio, salts)) > 0.9

def test_split():
    p = password.hash("somestuff", do_serialize=True)
    assert type(password.split(p)) is password.HashedPassword

def stagger(it):
    a, b = tee(it)
    next(b)
    return izip(a,b)

def test_hash():
    hs = [password.hash(n).hash for n in big_pile_o_names]
    assert all(len(a) == len(b) for a, b in stagger(hs))
    assert not any(a == b for a, b in stagger(hs))
    ave_ratio = mean(map(compression_ratio, hs))
    assert 0.9 < ave_ratio < 1.1


def test_hash_unicode():
    password.hash(u'\xc3bermensch')
    

def test_serialize():
    assert type(password.serialize(password.hash("blahblah"))) is str

def test_token():
    tok, bdate = password.token()
    assert len(tok) == password.DEFAULT_AUTHKEY_LEN
    assert type(bdate) is float
    assert bdate <= time.time()
    assert len(password.token(8)[0]) == 8
    t = time.time()-300
    assert password.token(the_time=t)[1] == t

    ts = [password.token()[0] for _ in range(100)]
    assert mean(map(compression_ratio, ts)) > 0.6

def test_is_serialized():
    p = password.hash("hithere", do_serialize=False)
    assert password.is_serialized(p) == False
    p = password.serialize(p)
    assert password.is_serialized(p) == True
    
