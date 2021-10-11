from utils.process_inputs import process_inputs, count_process_inputs
from multiprocessing import Process, Queue, Manager
import queue
import time
import traceback
from threading import Thread
from tqdm import tqdm
import json

STOP_WAIT_SECS = 1

manager = Manager()

pg_lock = manager.RLock()
tqdm.set_lock(pg_lock)

def dispatch_targets(targets, static_inputs, worker_func, func_args, workers=10, process=True, pg_name=None, resume=0):
    # Parse inputs
    target_gen = process_inputs(targets, static_inputs)
    target_size = count_process_inputs(targets, static_inputs)

    dispatch(target_gen, target_size, worker_func, func_args, workers=workers, process=process, pg_name=pg_name, resume=resume)

def dispatch(gen, gen_size, worker_func, func_args, workers=10, process=True, pg_name=None, resume=0):
    try:
        worker_list = []

        if process:
            n_process = int(workers/100+1)
            n_threads = int(workers/n_process)
        else:
            n_threads = int(workers)

        # prepare progress bar thread
        pg_queue = manager.Queue()
        pg_thread = Thread(target=progressbar_worker, args=(gen_size, pg_queue, pg_name))
        pg_thread.daemon = True
        pg_thread.start()

        # Progress bar started, now resuming
        if resume > 0:
            tqdm.write("Resuming to value: %d" % resume)
            for _ in range(resume):
                try:
                    next(gen)
                    pg_queue.put(1)
                except StopIteration:
                    break

        if process:
            n_all = n_threads*n_process
        else:
            n_all = n_threads

        # Start feeding worker
        feed_queue = manager.Queue()
        feed_thread = Thread(target=feedqueue_worker, args=(gen, feed_queue, n_all))
        feed_thread.daemon = True
        feed_thread.start()

        if process:
            # Start processes
            for _ in range(n_process):
                p = Process(target=process_worker, args=(feed_queue, worker_func, func_args, pg_queue, n_threads))
                p.start()
                worker_list.append(p)
        else:
            for _ in range(n_threads):
                t = Thread(target=thread_worker, args=(feed_queue, worker_func, func_args, pg_queue))
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

def process_worker(feed_queue, worker_func, func_args, pg_queue, n_threads):
    try:
        thread_list = []

        for _ in range(n_threads):
            t = Thread(target=thread_worker, args=(feed_queue, worker_func, func_args, pg_queue))
            t.daemon = True
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()
    except KeyboardInterrupt:
        pass

def thread_worker(feed_queue, worker_func, func_args, pg_queue):
    try:
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
    except KeyboardInterrupt:
        pass

def progressbar_worker(target_size, pg_queue, pg_name):

    if pg_name == None:
        pg = tqdm(total=target_size, mininterval=1, leave=False)
    else:
        pg = tqdm(total=target_size, mininterval=1, desc=pg_name, leave=False)
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

    time.sleep(1)

    pg.close()

def feedqueue_worker(target_gen, feed_queue, nb_workers):
    try:
        for target in target_gen:
            feed_queue.put(json.dumps(target))

    except BrokenPipeError:
        pass
    except Exception as e:
        print("%s: %s" % (type(e), e))
