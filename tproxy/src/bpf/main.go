package main

import (
	"encoding/binary"
	"log"
	// "net"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"fmt"
)

func main() {
	var err error
	rlimit.RemoveMemlock()
	var targetPort uint16 = 1003
	fmt.Printf("0x%x\n", targetPort)
	pointer := unsafe.Pointer(&targetPort)
	point := (*[4]byte)(pointer)[:]
	for _, v := range point {
		fmt.Printf("0x%x ", v)
	}
	fmt.Printf("\n")
	x := binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&targetPort))[:])
	fmt.Printf("0x%x\n", x)
	var proxyPort uint16 = 9999
	// proxyAddr := "127.0.0.1"
	var proxyAddr uint32 = 0x7f000001

	spec, err := loadTproxy()
	if err != nil {
		log.Fatalf("loadTproxy")
	}

	spec.RewriteConstants(map[string]interface{}{
		"target_port": binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&targetPort))[:]),
		"proxy_port": binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&proxyPort))[:]),
		"proxy_addr": binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&proxyAddr))[:]),
		// "proxy_addr": binary.BigEndian.Uint32([]byte(net.ParseIP(proxyAddr).To4())),
	})

	var obj tproxyObjects
	var op ebpf.CollectionOptions
	err = spec.LoadAndAssign(&obj, &op)
	if err != nil {
		log.Fatalf("loadAndAssign:%v\n", err)
	}

	defer obj.Close()


	link, err := netlink.LinkByName("lo")
	if err != nil {
		log.Fatalf("netlink.LinkByName: %v\n", err)
	}

	if err := addQdisc(link); err != nil {
		log.Fatalf("addQdisc: %v\n", err)
	}
	if err := filterAddBpf(link, obj.Tproxy); err != nil {
		log.Fatalf("filterAddBpf: %v\n", err)
	}

	fmt.Fprintf(os.Stdout, "attach bpf program to %s\n", link.Attrs().Name)
}

func addQdisc(link netlink.Link) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscDel(qdisc); err != nil {
		fmt.Println(err.Error(), "ignore")
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("qdiscAdd: %v", err)
	}

	return nil
}


func filterAddBpf(link netlink.Link, prog *ebpf.Program) error {
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0, 1),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Priority:  1,
		Protocol:  unix.ETH_P_ALL,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           prog.FD(),
		Name:         "rtn_tc_redirect",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("filterAdd: %v", err)
	}

	return nil
}