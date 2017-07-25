import progressbar,time
def eta():
    sleep_time = 50
    widgets = ['<sleep time: ', str(sleep_time), '> ', progressbar.Percentage(), ' ', progressbar.Bar(marker=progressbar.RotatingMarker('>-=#')),' ', progressbar.ETA()]
    bar = progressbar.ProgressBar(widgets=widgets, maxval=50).start()
    for i in bar(range(sleep_time)):
       time.sleep(1)
    bar.finish()
eta()
