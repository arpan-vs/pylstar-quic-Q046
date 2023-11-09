f=open("lsquic_Q046_http_reference_dump.txt","r")
name="lsquic_Q046_reference_converted_dump.txt"
g=open(name,"w")
i=0
s=0
dump=f.read()
for i in range(len(dump)):
        if i+1 < len(dump):
                g.write((dump[i]+dump[i+1]).upper()) 
                i=i+3