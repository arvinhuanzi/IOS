//
//  main.cpp
//  RtpToAAC
//
//  Created by luozhuang on 17/3/8.
//  Copyright © 2017年 arvin. All rights reserved.
//

#include <iostream>

//int main(int argc, const char * argv[]) {
//    // insert code here...
//    std::cout << "Hello, World!\n";
//    
//    //打开源文件
//    const char *fileNameRTP="";
//    
//    FILE *fileRTP=fopen(fileNameRTP, "a+");
//    
//    //打开需要过滤文件
//    const char *fileNameAAC="";
//    FILE *fileAAC=fopen(fileNameAAC, "w+");
//    
//    void *data;
//    size_t size=0;
//    
//    size_t fread(data, size, <#size_t __nitems#>, fileRTP);
//    
//    
//    while (1) {
//        
//        
//        
//    }
//    
//    
//    return 0;
//}
#ifndef __FF_TCPIP_H__
#define __FF_TCPIP_H__

#define __LITTLE_ENDIAN_BITFIELD

typedef  int int32;
typedef  unsigned int u_int32;
typedef  unsigned char u_char;
typedef  unsigned short u_short;


typedef struct ip_hdr{//ipv4头部
#ifdef __LITTLE_ENDIAN_BITFIELD
    u_char ip_length:4,
ip_version:4;
#else
    u_char ip_version:4,
ip_length:4;
#endif
    u_char ip_tos;
    u_short ip_total_length;
    u_short ip_id;
    u_short ip_flags;
    u_char ip_ttl;
    u_char ip_protocol;
    u_short ip_cksum;
    u_int32 ip_source;
    u_int32 ip_dest;
}__attribute__((packed)) IP_HDR;

typedef struct udp_hdr{//udp头部
    u_short s_port;
    u_short d_port;
    u_short length;
    u_short cksum;
}__attribute__((packed)) UDP_HDR;

typedef struct psd_header{//伪头部，用于计算校验和
    u_int32 s_ip;//source ip
    u_int32 d_ip;//dest ip
    u_char mbz;//0
    u_char proto;//proto type
    u_short plen;//length
}__attribute__((packed)) PSD_HEADER;

typedef struct _MAC_FRAME_HEADER{
    char m_cDstMacAddress[6];   //目的mac地址
    char m_cSrcMacAddress[6];   //源mac地址
    short m_cType;              //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
}__attribute__((packed)) MAC_FRAME_HDR;

typedef struct {
#ifdef __LITTLE_ENDIAN_BITFIELD   //注意，各个机器大端小端是不同的，所以要根据实际情况修改此宏定义
    u_char csrc_count:4,
extension:1,
padding:1,
version:2;
    u_char payload_type:7,
marker:1;
#else
    u_char version:2, //RTP协议的版本号，占2位，当前协议版本号为2
padding:1, //填充标志，占1位，如果P=1，则在该报文的尾部填充一个或多个额外的八位组，它们不是有效载荷的一部分
extension:1, //扩展标志，占1位，如果X=1，则在RTP报头后跟有一个扩展报头。
csrc_count:4; //CSRC计数器，占4位，指示CSRC 标识符的个数
    u_char  marker:1, //不同的有效载荷有不同的含义，对于视频，标记一帧的结束；对于音频，标记会话的开始
payload_type:7; //有效载荷类型，占7位，用于说明RTP报文中有效载荷的类型，如GSM音频、JPEM图像等
#endif
    u_short seq; //序列号：占16位，用于标识发送者所发送的RTP报文的序列号，每发送一个报文，序列号增1
    u_int32 timestamp; //时戳：占32位，时戳反映了该RTP报文的第一个八位组的采样时刻。使用时戳来计算延迟和延迟抖动
    u_int32 ssrc; //占32位，用于标识同步信源。该标识符是随机选择的，参加同一视频会议的两个同步信源不能有相同的SSRC
}__attribute__((packed)) RTP_HDR;


typedef struct pcap_file_header {
    u_int32 magic;
    u_short version_major;
    u_short version_minor;
    int32   thiszone;
    u_int32 sigfigs;
    u_int32 snaplen;
    u_int32 linktype;
}__attribute__((packed)) PCAP_FILE_HDR;


typedef struct pcap_pkthdr {
    u_int32 iTimeSecond;
    u_int32 iTimeSS;
    u_int32 caplen;
    u_int32 len;        
}__attribute__((packed)) PCAP_PKT_HDR;

#endif

FILE *FileIn;
FILE *FileOut;

#define BUFFER_SIZE  1024*32
#define BOTTOM_ALERT  3000

//

int main(int argc, char *argv[]){
    
    const char *file_name = "recv_h264.h264";
   char abs_path_buff[PATH_MAX];
    //获取文件路径, 填充到abs_path_buff
     //realpath函数返回: null表示获取失败; 否则返回指向abs_path_buff的指针
   if(realpath(file_name, abs_path_buff)){
         printf("%s %s\n", file_name, abs_path_buff);
       }
     else{
           printf("the file '%s' is not exist\n", file_name);
        }
    
    char filein[100]="aac_pcap.pcap";
    char fileout[100]="2222.data";
    char buffer[BUFFER_SIZE];
    char *pos;
    int len_pkt_left,  //包的剩余长度
    len_read ,
    len_read_left, //剩余长度
    read_to_end=0 , //是否读取到文件尾
    len_alert = BOTTOM_ALERT; //警戒长度，当操作指针距离缓冲区末尾小于这个值的时候，就将剩余部分移动到缓冲区头
    PCAP_PKT_HDR *pcap_pkt_hdr;
    RTP_HDR *rtp_hdr;
    
//    if(argc < 3){
//        printf("input err!!! \n");
//        exit(1) ;
//    }
//    strcpy(filein, argv[1]);
//    strcpy(fileout,argv[2]);
    FileIn = fopen(filein,"rb");
    FileOut = fopen(fileout,"wb");
    if(FileIn == NULL || FileOut==NULL){
        printf("open err!!!!\n");
        exit(1);
    }
    
    //偏移PCAP文件头
    fseek(FileIn,sizeof(PCAP_FILE_HDR),SEEK_SET);
    pos = buffer;
    len_read = fread(buffer, sizeof(char), BUFFER_SIZE ,FileIn);
    do{
        //如果文件读到底了，就全解析完。 否则缓冲区剩余字节小于BOTTOM_ALERT的时候退出循环
        while( pos - buffer <  len_read - len_alert){
            pcap_pkt_hdr = (PCAP_PKT_HDR *)pos;
            len_pkt_left = pcap_pkt_hdr->caplen;
            pos += sizeof(PCAP_PKT_HDR);
            
            pos += (sizeof(MAC_FRAME_HDR) + sizeof(IP_HDR) +  sizeof(UDP_HDR));
            len_pkt_left -=  (sizeof(MAC_FRAME_HDR) + sizeof(IP_HDR) +  sizeof(UDP_HDR));
            
            rtp_hdr = (RTP_HDR*)pos;
            pos += sizeof(RTP_HDR);
            len_pkt_left -= sizeof(RTP_HDR);
            
            //pos 终于指向payload了
            pos += (rtp_hdr->csrc_count) * sizeof(int);
            len_pkt_left -= (rtp_hdr->csrc_count) * sizeof(int);
            
            fwrite(pos, 1,len_pkt_left, FileOut);
            //pos 指向下一个pcap 包头的地址
            pos += len_pkt_left;
        }
        if(read_to_end)
            break;
        len_read_left = len_read -(pos- buffer);
        printf("len_read_left [%d]\n", len_read_left);
        //将剩余部分移动到缓冲区头 然后继续从文件中读取 BUFFER_SIZE - len_read_left 这么长
        memmove(buffer,pos,len_read_left);
        pos = buffer + len_read_left;
        len_read = fread(pos, sizeof(char), (BUFFER_SIZE - len_read_left),FileIn);
        if(len_read < BUFFER_SIZE - len_read_left ){ //如果读到文件尾，就把警戒值置0，让下一个循环读完
            read_to_end =1 ;
            len_alert = 0;
        }
        //待处理的长度为  剩余部分 + 新读取部分
        len_read += len_read_left;
        pos = buffer;
    }while(1);
    return 0;
}
