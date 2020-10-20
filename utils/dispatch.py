from utils.process_inputs import process_inputs, count_process_inputs
from utils.output import Output
from multiprocessing import Process, Queue
import queue
import time
import traceback
from threading import Thread
from tqdm import tqdm
import json

STOP_WAIT_SECS = 1

def dispatch(targets, static_inputs, worker_func, func_args, workers=10):
    process_list = []

    n_process = int(workers/100+1)
    n_threads = int(workers/n_process)

    # Parse inputs
    target_gen = process_inputs(targets, static_inputs)
    target_size = count_process_inputs(targets, static_inputs)

    # prepare progress bar thread
    pg_queue = Queue()
    pg_thread = Thread(target=progressbar_worker, args=(target_size, pg_queue))
    pg_thread.daemon = True
    pg_thread.start()

    # Start feeding worker
    feed_queue = Queue()
    feed_thread = Thread(target=feedqueue_worker, args=(target_gen, feed_queue, n_threads*n_process))
    feed_thread.daemon = True
    feed_thread.start()

    # Start processes
    for _ in range(n_process):
        p = Process(target=process_worker, args=(feed_queue, worker_func, func_args, pg_queue, n_threads)) 
        p.start()
        process_list.append(p)

    pg_thread.join()

    num_terminated = 0
    num_failed = 0  
    end_time = time.time() + STOP_WAIT_SECS
    for p in process_list:
        join_secs = max(0.0, min(end_time - time.time(), STOP_WAIT_SECS))
        p.join(join_secs)

    while process_list:
        proc = process_list.pop()
        if proc.is_alive():
            proc.terminate()
            num_terminated += 1
        else:
            exitcode = proc.exitcode
            if exitcode:
                num_failed += 1

def process_worker(feed_queue, worker_func, func_args, pg_queue, n_threads):
    thread_list = []

    for _ in range(n_threads):
        t = Thread(target=thread_worker, args=(feed_queue, worker_func, func_args, pg_queue))
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

def thread_worker(feed_queue, worker_func, func_args, pg_queue):
    while True:
        target = json.loads(feed_queue.get())

        if target == None:
            break
        
        try:
            worker_func(target, *func_args)
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))
        finally:
            pg_queue.put(1)
           
def progressbar_worker(target_size, pg_queue):
    pg = tqdm(total=target_size, mininterval=1)
    count = 0

    while True:
        try:
            c = pg_queue.get(True, 0.1)
        except queue.Empty:
            c = 0
        except Exception as e:
            c = 0
        count += c
        pg.update(c)
        pg.refresh()

        if count >= target_size:
            break

    pg_queue.close()

def feedqueue_worker(target_gen, feed_queue, nb_workers):
    try:
        for target in target_gen:
            feed_queue.put(json.dumps(target))

    except Exception as e:
        print("%s: %s" % (type(e), e))
