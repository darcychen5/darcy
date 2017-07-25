import progressbar,time,os
bar = progressbar.ProgressBar().start()
for i in bar(range(300)):
	time.sleep(1)
bar.finish()
