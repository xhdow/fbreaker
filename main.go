package main

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 用以等待所有任务执行完
var wg sync.WaitGroup

// 遍历目录时的统计信息
type WalkStat struct {
	totalFiles   uint64 //总文件数,包含目录、文件、符号链接等所有项
	regularFiles uint64 //普通文件数
	failedFiles  uint64 //访问失败文件数
}

// 为遍历到的每个普通文件回调 fn(filepath,args)
type WalkFileCallback func(string, string)

// 遍历目录及子目录下的所有文件。
// indent: 打印遍历到的文件时，各级文件的缩进字符数。
// verbose: 是否打印出扫描到的文件信息。
// wstat: 扫描过程中的一些统计数据
// fn: 对每一个普通文件，回调此函数
// args: 传递给 fn 的第二个参数
func WalkFiles(root string, indent int, verbose bool, wstat *WalkStat, fn WalkFileCallback, args string) error {
	files, e := os.ReadDir(root)

	if e != nil {
		wstat.failedFiles++
		fmt.Printf("e=%v  %v\n", e, root)
		return e
	}
	for _, v := range files {
		wstat.totalFiles++
		if verbose == true {
			fmt.Printf(strings.Repeat("-", indent)+"%v\n", v.Name())
		}
		fpath := filepath.Join(root, v.Name())

		//如果不是普通文件，就当做目录进一步遍历
		if v.Type().IsRegular() == false {
			WalkFiles(fpath, indent+4, verbose, wstat, fn, args)
		} else {
			wstat.regularFiles++
			if fn != nil {
				wg.Add(1)
				fn(fpath, args) //对普通文件回调
			}
		}

	}
	return nil
}

// 解密版本为 XXXX 的文件
func decode_XXXX(fpath string, pwd string) {
	finfo, _ := os.Stat(fpath)
	fmt.Printf("decoding %v\n", fpath)
	f, e := os.OpenFile(fpath, os.O_RDWR, 0666)
	if e != nil {
		fmt.Printf("****err:failed to open %s\n", fpath)
		return
	}
	defer f.Close()

	var n int = 0
	var encrypt_nbytes int64 = 64
	var bs_ver []byte = make([]byte, 4)
	var bs_fname_size []byte = make([]byte, 4)
	f.Seek(-4, 2)
	f.Read(bs_ver)
	if string(bs_ver) != "XXXX" {
		fmt.Printf("**not-encrypted:%v:%v\n", bs_ver, fpath)
		return
	}
	f.Seek(-8, 2)
	f.Read(bs_fname_size)
	var fname_size int32 = 0
	fname_size = int32(bs_fname_size[0])<<24 | int32(bs_fname_size[1])<<16 |
		int32(bs_fname_size[2])<<8 | int32(bs_fname_size[3])

	var bs_fname []byte = make([]byte, fname_size)
	f.Seek(int64(0-fname_size-8), 2)
	f.Read(bs_fname)
	fname := string(bs_fname)

	var bs_md5 []byte = make([]byte, 16)
	f.Seek(int64(0-fname_size-8-16), 2)
	f.Read(bs_md5)

	h := md5.New()
	io.WriteString(h, pwd)
	pwd_md5 := h.Sum(nil)
	fmt.Printf("--meta:%X,%v,%v\n", bs_ver, fname_size, fname)

	if string(bs_md5) != string(pwd_md5) {
		fmt.Printf("**err:pwd:%s\n", fpath)
		return
	}
	fmt.Println("--ok:true")

	f.Seek(0, 0)
	var bs_data []byte = make([]byte, encrypt_nbytes)
	f.Read(bs_data)
	for i, v := range bs_data {
		bs_data[i] = v ^ pwd[0]
	}

	f.Seek(0, 0)
	n, e = f.Write(bs_data)
	if e != nil || n != int(encrypt_nbytes) {
		fmt.Println("**err:3258:write error:", fpath)
		return
	}

	f.Truncate(finfo.Size() - int64(fname_size) - 8 - 16)
	f.Close()
	os.Rename(fpath, filepath.Join(filepath.Dir(fpath), fname))

}

// 仅清除版本为 XXXX 的 metadata(即只删除文件是的 metadata，不做加密或解密处理)
func clear_XXXX_meta(fpath string, arg string) {
	finfo, _ := os.Stat(fpath)
	fmt.Printf("clearing %v\n", fpath)
	f, e := os.OpenFile(fpath, os.O_RDWR, 0666)
	if e != nil {
		fmt.Printf("****err:failed to open %s\n", fpath)
		return
	}
	defer f.Close()

	var bs_ver []byte = make([]byte, 4)
	var bs_fname_size []byte = make([]byte, 4)
	f.Seek(-4, 2)
	f.Read(bs_ver)
	if string(bs_ver) != "XXXX" {
		fmt.Printf("**not-encrypted:%v:%v\n", bs_ver, fpath)
		return
	}
	f.Seek(-8, 2)
	f.Read(bs_fname_size)
	var fname_size int32 = 0
	fname_size = int32(bs_fname_size[0])<<24 | int32(bs_fname_size[1])<<16 |
		int32(bs_fname_size[2])<<8 | int32(bs_fname_size[3])
	var bs_fname []byte = make([]byte, fname_size)
	f.Seek(int64(0-fname_size-8), 2)
	f.Read(bs_fname)
	fname := string(bs_fname)

	f.Truncate(finfo.Size() - int64(fname_size) - 8 - 16)
	f.Close()
	os.Rename(fpath, filepath.Join(filepath.Dir(fpath), fname))
	fmt.Println("clear ok")

}

// 加密文件，算法版本代号为 "XXXX"
func encode_XXXX(fpath string, pwd string) {
	finfo, _ := os.Stat(fpath)
	fmt.Printf("encoding %v\n", fpath)
	f, e := os.OpenFile(fpath, os.O_RDWR, 0666)
	if e != nil {
		fmt.Printf("**err:failed to open %s\n", fpath)
		return
	}
	defer f.Close()

	var n int = 0
	var encrypt_nbytes int64 = 64
	//如果文件太小，不加密
	if finfo.Size() < encrypt_nbytes+int64(8+16+len(finfo.Name())) {
		return
	}
	var bs_ver = []byte("XXXX")
	f.Seek(-4, 2)
	f.Read(bs_ver)
	if string(bs_ver) == "XXXX" {
		fmt.Printf("**err:already encoded:%s\n", fpath)
		return
	}

	var bs_fname_size [4]byte
	var bs_data []byte = make([]byte, encrypt_nbytes)

	f.Seek(0, 0)
	f.Read(bs_data)
	for i, v := range bs_data {
		bs_data[i] = pwd[0] ^ v
	}
	f.Seek(0, 0)
	n, e = f.Write(bs_data)
	if e != nil || n != int(encrypt_nbytes) {
		fmt.Println("**err:3269:write error:", fpath)
		return
	}

	h := md5.New()
	h.Write([]byte(pwd))
	var pwd_uuid []byte = h.Sum(nil)
	binary.Encode(bs_fname_size[:], binary.BigEndian, int32(len(finfo.Name())))

	f.Seek(0, 2)
	f.Write(pwd_uuid)
	f.Write([]byte(finfo.Name()))
	f.Write(bs_fname_size[:])
	f.Write([]byte("XXXX"))
	var s string = strconv.Itoa(time.Now().Nanosecond()) + strconv.Itoa(rand.Int())
	f.Close()
	os.Rename(fpath, filepath.Join(filepath.Dir(fpath), s[15:]))

	println("--ok:true")

}

func main() {
	var rootdir string = "."
	var pwd string = "123456"
	var cmd string = "-h"

	var nargs = len(os.Args)

	if nargs < 2 {
		fmt.Println("hello world")
		return
	}
	if nargs > 1 {
		cmd = os.Args[1]
	}
	if nargs > 2 {
		pwd = os.Args[2]
	}
	if nargs > 3 {
		rootdir = os.Args[3]
	}

	if cmd == "-h" {
		fmt.Println("fbreaker go version by sHadow\n---------------------------------")
		fmt.Println("    fbreaker [encode|decode|clearmeta] password dir_path")
		return
	}

	if cmd == "decode" {
		var wstat WalkStat
		WalkFiles(rootdir, 0, false, &wstat, decode_XXXX, pwd)
		fmt.Printf("walk stat:total:%v,regular:%v,fail:%v\n", wstat.totalFiles, wstat.regularFiles, wstat.failedFiles)
		return
	} else if cmd == "encode" {
		var wstat WalkStat
		var pwd2 string = "?"
		fmt.Print("input password again:")
		fmt.Scanln(&pwd2)
		if pwd2 != pwd {
			fmt.Println("password invalid")
			return
		}
		fmt.Println("")

		WalkFiles(rootdir, 0, false, &wstat, encode_XXXX, pwd)
		fmt.Printf("walk stat:total:%v,regular:%v,fail:%v\n", wstat.totalFiles, wstat.regularFiles, wstat.failedFiles)
		return

	} else if cmd == "clearmeta" {
		fmt.Println("clearing meta")
		var wstat WalkStat
		WalkFiles(rootdir, 0, false, &wstat, clear_XXXX_meta, pwd)
	} else {
		fmt.Println("command error")
	}

}
