from dumpulator import Dumpulator

dp = Dumpulator(".\\membp_2nd_hit.dmp", trace=True)
dp.start(dp.regs.rip)
