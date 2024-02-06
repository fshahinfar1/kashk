class Likelihood:
    Neutral  = 0
    Likely   = 1
    Unlikely = 2

    @classmethod
    def flip(cls, val):
        if val == Likelihood.Likely:
            return Likelihood.Unlikely
        elif val == Likelihood.Unlikely:
            return Likelihood.Likely
        else:
            return Likelihood.Neutral
