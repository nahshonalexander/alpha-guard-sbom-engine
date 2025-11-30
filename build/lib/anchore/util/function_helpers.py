from functools import wraps

#what is this decorator here? 

def trace(f):
    """ Tracing decorator """
    @wraps(f)
    def decorator(*args, **kwargs):
        print ('Calling ' + f.func_name + ' in ' + str(args[0]))
        return f(*args, **kwargs)
    return decorator