from threading import Thread,Event
import threading
from functools import wraps



 
def func(a):
    a+=1
    print('I\'m running %s',a)
    threading.Timer(5.0, func,[a]).start() 


func(0)



