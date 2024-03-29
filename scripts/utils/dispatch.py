from utils.process_inputs import process_inputs, count_process_inputs
from utils.config import Config
import sys
from multiprocessing import Process, Manager
import queue
import time
import os
import multiprocessing

import traceback
from threading import Thread
from tqdm import tqdm
import json

STOP_WAIT_SECS = 1

manager = Manager()

pg_lock = manager.RLock()
tqdm.set_lock(pg_lock)

def dispatch_targets(targets, static_inputs, worker_func, func_args, workers=10, process=True, pg_name=None, delay=0, resume=0):
    # Parse inputs
    target_gen = process_inputs(targets, static_inputs)
    target_size = count_process_inputs(targets, static_inputs)

    dispatch(target_gen, target_size, worker_func, func_args, workers=workers, process=process, pg_name=pg_name, delay=delay, resume=resume)

def dispatch(gen, gen_size, worker_func, func_args, workers=10, process=True, pg_name=None, delay=0, resume=0):

    try:
        worker_list = []

        if process:
            n_process = int(workers/100+1)
            n_threads = int(workers/n_process)
        else:
            n_threads = int(workers)

        # prepare progress bar thread
        pg_queue = multiprocessing.Queue()
        pg_thread = Thread(target=progressbar_worker, args=(gen_size, pg_queue, pg_name))
        pg_thread.daemon = True
        pg_thread.start()

        # Progress bar started, now resuming
        if resume > 0:
            tqdm.write("Resuming to value: %d" % resume)
            c = 0
            for _ in range(resume):
                try:
                    next(gen)
                    c += 1
                except StopIteration:
                    break
                if c == 50000:
                    pg_queue.put(c)
                    c = 0

            pg_queue.put(c)

        if process:
            n_all = n_threads*n_process
        else:
            n_all = n_threads

        # Start feeding worker
        feed_queue = multiprocessing.Queue()
        feed_thread = Process(target=feedqueue_worker, args=(gen, feed_queue, n_all, 10))
        feed_thread.daemon = True
        feed_thread.start()

        if process:
            # Start processes
            for _ in range(n_process):
                p = Process(target=process_worker, args=(feed_queue, worker_func, func_args, pg_queue, n_threads, delay))
                p.start()
                worker_list.append(p)
        else:
            for _ in range(n_threads):
                t = Thread(target=thread_worker, args=(feed_queue, worker_func, func_args, pg_queue, delay))
                t.start()
                worker_list.append(t)

        pg_thread.join()

    except KeyboardInterrupt:
        tqdm.write("Scan interrupted")
    finally:
        if process:
            num_terminated = 0
            num_failed = 0
            end_time = time.time() + STOP_WAIT_SECS
            for p in worker_list:
                join_secs = max(0.0, min(end_time - time.time(), STOP_WAIT_SECS))
                p.join(join_secs)

            while worker_list:
                proc = worker_list.pop()
                if proc.is_alive():
                    proc.terminate()
                    num_terminated += 1
                else:
                    exitcode = proc.exitcode
                    if exitcode:
                        num_failed += 1

def process_worker(feed_queue, worker_func, func_args, pg_queue, n_threads, delay):
    try:
        thread_list = []

        for _ in range(n_threads):
            t = Thread(target=thread_worker, args=(feed_queue, worker_func, func_args, pg_queue, delay))
            t.daemon = True
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()
    except KeyboardInterrupt:
        pass

def thread_worker(feed_queue, worker_func, func_args, pg_queue, delay):
    try:
        while True:
            target = json.loads(feed_queue.get())

            if target == None:
                break

            t0 = time.time()

            try:
                worker_func(target, *func_args)
            except Exception as e:
                print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))
                # Store the exception for debugging purposes

                log_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "..", Config.config.get('Logging', 'folder'), "stack_traces.log")
                logfile = open(log_path, "a")
                logfile.write("%s: %s\n%s: %s\n%s\n\n" % (str(worker_func), str(target), type(e), e, traceback.format_exc()))
                logfile.close()
            finally:
                pg_queue.put(1)

                time_spent = time.time() - t0

                if time_spent < delay:
                    time.sleep(delay - time_spent)

    except KeyboardInterrupt:
        pass

def progressbar_worker(target_size, pg_queue, pg_name):

    if pg_name == None:
        pg = tqdm(total=target_size, mininterval=1, leave=False, dynamic_ncols=True)
    else:
        pg = tqdm(total=target_size, mininterval=1, desc=pg_name, leave=False, dynamic_ncols=True)
    count = 0

    c = 0
    update = False
    while True:
        try:
            c += pg_queue.get(True, 0.1)
        except queue.Empty:
            update = True
        except Exception as e:
            pass

        if update or c >= 10:
            count += c
            pg.update(c)
            pg.refresh()
            c = 0
            update = False

        if count >= target_size:
            break

    time.sleep(1)

    pg.close()

def feedqueue_worker(target_gen, feed_queue, nb_workers, bulk_nb):
    try:
        for target in target_gen:
            feed_queue.put(json.dumps(target))

    except BrokenPipeError:
        pass
    except Exception as e:
        print("%s: %s" % (type(e), e))
