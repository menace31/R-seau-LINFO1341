import pyshark
import matplotlib.pyplot as plt

timestamps = []
sizes = [0,0,0] # audio, video, screenshare
total_sizes = [0,0,0]
audio_sizes = []
video_sizes = []
scrns_sizes = []
minutes = []
start = 0
i = 0

# Open the pcapng file using Pyshark
cap = pyshark.FileCapture('all_packets.pcapng', display_filter='rtp')

# Iterate through each packet and extract the timestamp and size of RTP packets
for pkt in cap:
    # Check if the packet contains RTP payload
    if 'rtp' in pkt:
        if 'UDP' in pkt:
            udp = pkt.udp
            ts = float(pkt.sniff_time.timestamp())
            ztype = int(pkt.zoom.type) #13=screen share, 15=audio, 16=video
            
  
            if start == 0: start = ts
            
            if start != 0:
                ul = int(udp.length) - 8
                if ztype == 13: # for screen share
                    sizes[2] += ul  
                    total_sizes[2] += ul
                elif ztype == 15: #for audio
                    sizes[0] += ul  
                    total_sizes[0] += ul
                elif ztype == 16: #for video
                    sizes[1] += ul  
                    total_sizes[1] += ul
                
                

            if ts >= start + 60*i:
                    i += 0.5
                    print(sizes)
                    audio_sizes.append(sizes[0])
                    video_sizes.append(sizes[1])
                    scrns_sizes.append(sizes[2])
                    sizes = [0,0,0]
                    minutes.append(i)
                    
cap.close()

def video_and_audio(t,sv,sa,ss):
    plt.plot(t, sv, label='Video: ' + str(total_sizes[1]) + ' bytes')
    plt.plot(t, sa, label='Audio:   '+ str(total_sizes[0]) + ' bytes')
    plt.plot(t, ss, label='Scrn:     '+ str(total_sizes[2]) + ' bytes')
    plt.xlim(t[0], t[-1])
    plt.xlabel('Time (min)')
    plt.ylabel('RTP Packet Size')
    plt.title('RTP Packet Size vs Time')
    plt.legend()
    plt.show()



video_and_audio(minutes,video_sizes,audio_sizes,scrns_sizes)

