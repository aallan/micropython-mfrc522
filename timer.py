from utime import ticks_ms, ticks_diff

log = True
timers = {}
depth = 0
whitespace = "  "
def startTimer(name):
    timers[name] = ticks_ms()
    indent = whitespace * depth
    if log:
        print("{}{} started".format(indent, name))

def endTimer(name):
    if name in timers:
        startms = timers[name]
        sincems = ticks_diff(ticks_ms(), startms)
        indent = whitespace * depth
        if log:
            print("{}{} took {}ms".format(indent, name, sincems))
        del timers[name]
    else:
        print("NO SUCH TIMER '{}' !".format(name))

def timeit(timerName):
    def factory(method):
        def timed(*args, **kw):
            global depth
            try:
                startTimer(timerName)
                depth += 1
                result = method(*args, **kw)
                depth -= 1
            finally:
                endTimer(timerName)
            return result
        return timed
    return factory