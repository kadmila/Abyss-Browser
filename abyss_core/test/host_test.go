package test

import (
	"context"
	"crypto/ed25519"
	crypto_rand "crypto/rand"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"
	abyss_host "github.com/kadmila/Abyss-Browser/abyss_core/host"
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"

	"github.com/google/uuid"
)

func _time_passed(time_begin time.Time) string {
	return strconv.FormatFloat(float64(time.Since(time_begin).Milliseconds())/1000.0, 'f', 3, 32)
}

func printWorldEvents(time_begin time.Time, prefix string, host abyss.IAbyssHost, world abyss.IAbyssWorld, dwell_time_ms int, joiner_ch chan string, fin_ch chan bool) {
	ev_ch := world.GetEventChannel()

	members := make(map[string]bool)
	timeout := time.After(time.Duration(dwell_time_ms) * time.Millisecond)
	for {
		select {
		case <-timeout:
			host.LeaveWorld(world) //this immediately returns
			fmt.Println(_time_passed(time_begin) + prefix + " Left World: " + world.SessionID().String())
			fin_ch <- true
			return
		case joiner_aurl := <-joiner_ch:
			parsed_aurl, err := aurl.TryParse(joiner_aurl)
			if err != nil {
				panic(err.Error())
			}
			host.OpenOutboundConnection(parsed_aurl)
		case event_unknown := <-ev_ch:
			switch event := event_unknown.(type) {
			case abyss.EWorldMemberRequest:
				fmt.Println(_time_passed(time_begin) + prefix + " accepting " + event.MemberHash)

				if _, ok := members[event.MemberHash]; ok {
					panic("!!! duplicate peer session request !!!")
				}
				members[event.MemberHash] = false // member not ready

				event.Accept()
			case abyss.EWorldMemberReady:
				fmt.Println(_time_passed(time_begin) + prefix + " peer ready: " + event.Member.Hash())

				is_ready, ok := members[event.Member.Hash()]
				if !ok {
					panic("!!! non-member peer ready !!!")
				}
				if is_ready {
					panic("!!! duplicate peer ready !!!")
				}
				members[event.Member.Hash()] = true // ready

				//event.Peer.AppendObjects([]abyss.ObjectInfo{abyss.ObjectInfo{ID: uuid.New(), Address: "https://abyssal.com/cat.obj"}})
			case abyss.EMemberObjectAppend:
				fmt.Println(_time_passed(time_begin) + prefix + " " + event.PeerHash + " appended" + functional.Accum_all(event.Objects, "", func(obj abyss.ObjectInfo, accum string) string {
					return accum + " " + obj.ID.String() + "|" + obj.Addr
				}))
			case abyss.EMemberObjectDelete:
				fmt.Println(_time_passed(time_begin) + prefix + " " + event.PeerHash + " deleted" + functional.Accum_all(event.ObjectIDs, "", func(obj uuid.UUID, accum string) string { return accum + " " + obj.String() }))
			case abyss.EWorldMemberLeave:
				fmt.Println(_time_passed(time_begin) + prefix + " peer leave: " + event.PeerHash)

				if _, ok := members[event.PeerHash]; !ok {
					panic("!!! non-member peer leave !!!")
				}
				delete(members, event.PeerHash)
			default:
				panic("unknown world event")
			}
		}
	}
}

func TestHost(t *testing.T) {
	time_begin := time.Now()
	_, privkey, err := ed25519.GenerateKey(crypto_rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostA, hostA_pathMap, _ := abyss_host.NewBetaAbyssHost(context.Background(), &privkey, nil)
	_, privkey, err = ed25519.GenerateKey(crypto_rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostB, _, _ := abyss_host.NewBetaAbyssHost(context.Background(), &privkey, nil)

	go hostA.ListenAndServe(context.Background())
	go hostB.ListenAndServe(context.Background())

	hostA.NetworkService.AppendKnownPeer(hostB.NetworkService.LocalIdentity().RootCertificate(), hostB.NetworkService.LocalIdentity().HandshakeKeyCertificate())
	hostB.NetworkService.AppendKnownPeer(hostA.NetworkService.LocalIdentity().RootCertificate(), hostA.NetworkService.LocalIdentity().HandshakeKeyCertificate())

	A_world, err := hostA.OpenWorld("http://a.world.com")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("[" + hostA.GetLocalAbyssURL().Hash + "] Opened World: " + A_world.SessionID().String())
	hostA_pathMap.TrySetMapping("/home", A_world.SessionID()) //this opens the world for join from A's side
	A_world_fin := make(chan bool, 1)
	go printWorldEvents(time_begin, "["+hostA.GetLocalAbyssURL().Hash+"]", hostA, A_world, 30000, make(chan string, 1), A_world_fin)

	<-time.After(100 * time.Millisecond)
	hostA.OpenOutboundConnection(hostB.GetLocalAbyssURL())

	join_url := hostA.GetLocalAbyssURL()
	join_url.Path = "/home"

	fmt.Println("[" + hostB.GetLocalAbyssURL().Hash + "] Joining World")
	join_ctx, join_ctx_cancel := context.WithTimeout(context.Background(), time.Second)
	B_A_world, err := hostB.JoinWorld(join_ctx, join_url)
	join_ctx_cancel()

	if err != nil {
		t.Fatal("[" + hostB.GetLocalAbyssURL().Hash + "] Join Failed:::" + err.Error())
	}
	fmt.Println("[" + hostB.GetLocalAbyssURL().Hash + "] Joined World: " + B_A_world.SessionID().String())

	B_A_world_fin := make(chan bool, 1)
	go printWorldEvents(time_begin, "["+hostB.GetLocalAbyssURL().Hash+"]", hostB, B_A_world, 30000, make(chan string, 1), B_A_world_fin)

	<-A_world_fin
	<-B_A_world_fin
}

func RandomBoolean() bool {
	return rand.Intn(2) == 1
}

func RandomString() string {
	chars := []rune("abcdefghijklmnopqrstuvwxyz")

	// Create a slice of runes to hold our random characters
	result := make([]rune, 3)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}

	return string(result)
}

type GlobalWorldRegistry struct {
	list map[string]struct {
		join_aurl string
		wait_ch   chan string
	} //some key -> aurl.
	mtx *sync.Mutex
}

func NewGlobalWorldRegistry() *GlobalWorldRegistry {
	return &GlobalWorldRegistry{
		list: make(map[string]struct {
			join_aurl string
			wait_ch   chan string
		}),
		mtx: new(sync.Mutex),
	}
}
func (g *GlobalWorldRegistry) Append(key, entry string, waiter_ch chan string) {
	g.mtx.Lock()
	defer g.mtx.Unlock()
	if _, ok := g.list[key]; ok {
		panic("same key in GlobalWorldRegistry")
	}
	g.list[key] = struct {
		join_aurl string
		wait_ch   chan string
	}{entry, waiter_ch}
}

func (g *GlobalWorldRegistry) Delete(key string) {
	g.mtx.Lock()
	defer g.mtx.Unlock()
	delete(g.list, key)
}
func (g *GlobalWorldRegistry) RequestRandom(local_aurl string) (string, bool) {
	g.mtx.Lock()
	defer g.mtx.Unlock()
	if len(g.list) == 0 {
		return "", false
	}

	keys := make([]string, 0, len(g.list))
	for k := range g.list {
		keys = append(keys, k)
	}

	targ_key := keys[rand.Intn(len(g.list))]
	entry := g.list[targ_key]
	entry.wait_ch <- local_aurl
	return entry.join_aurl, true
}

type AutonomousHost struct {
	global_join_targets *GlobalWorldRegistry
	abyss_host          *abyss_host.AbyssHost
	abyss_pathMap       *abyss_host.SimplePathResolver
	log_prefix          string
}

func (a *AutonomousHost) Run(ctx context.Context, time_begin time.Time, done_ch chan bool) {
	defer func() {
		done_ch <- true
	}()
	go a.abyss_host.ListenAndServe(context.Background())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			fmt.Println(_time_passed(time_begin) + a.log_prefix + "next round")
			if RandomBoolean() {
				fmt.Println(_time_passed(time_begin) + a.log_prefix + "A) open")
				world_name := RandomString()
				world, err := a.abyss_host.OpenWorld("https://" + world_name + ".com")
				if err != nil {
					panic(err.Error())
				}
				dwell_time := rand.Intn(10000)
				fmt.Println(_time_passed(time_begin) + a.log_prefix + " Opened world: " + world.SessionID().String() + "/" + world_name + " -(" + strconv.Itoa(dwell_time) + "ms)")
				a.abyss_pathMap.TrySetMapping("/"+world_name, world.SessionID())

				raw_aurl := a.abyss_host.GetLocalAbyssURL()
				raw_aurl.Path = "/" + world_name
				joiner_ch := make(chan string, 16)
				a.global_join_targets.Append(a.log_prefix+world_name, raw_aurl.ToString(), joiner_ch)

				printWorldEvents(time_begin, a.log_prefix, a.abyss_host, world, dwell_time, joiner_ch, make(chan bool, 1))

				a.abyss_pathMap.DeleteMapping("/" + world_name)
				a.global_join_targets.Delete(a.log_prefix + world_name)
			} else {
				fmt.Println(_time_passed(time_begin) + a.log_prefix + "B) join")
				join_target_string, ok := a.global_join_targets.RequestRandom(a.abyss_host.GetLocalAbyssURL().ToString())
				if !ok {
					fmt.Println(a.log_prefix + "no join target")
					continue
				}
				join_target, err := aurl.TryParse(join_target_string)
				if err != nil {
					panic(err.Error())
				}

				fmt.Println(_time_passed(time_begin) + a.log_prefix + " Joining world: " + join_target.ToString())
				join_ctx, join_ctx_cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				world, err := a.abyss_host.JoinWorld(join_ctx, join_target)
				if err != nil {
					fmt.Println("join fail: " + err.Error())
					join_ctx_cancel()
					return
				}
				join_ctx_cancel()

				dwell_time := rand.Intn(10000)
				fmt.Println(_time_passed(time_begin) + a.log_prefix + " Joined world: " + world.SessionID().String() + " -(" + strconv.Itoa(dwell_time) + "ms)")
				world_name := RandomString()
				a.abyss_pathMap.TrySetMapping("/"+world_name, world.SessionID())

				raw_aurl := a.abyss_host.GetLocalAbyssURL()
				raw_aurl.Path = "/" + world_name
				joiner_ch := make(chan string, 16)
				a.global_join_targets.Append(a.log_prefix+world_name, raw_aurl.ToString(), joiner_ch)

				printWorldEvents(time_begin, a.log_prefix, a.abyss_host, world, dwell_time, joiner_ch, make(chan bool, 1))

				a.abyss_pathMap.DeleteMapping("/" + world_name)
				a.global_join_targets.Delete(a.log_prefix + world_name)
			}
		}
	}
}

func TestMoreHosts(t *testing.T) {
	N_hosts := 5

	global_world_reg := NewGlobalWorldRegistry()

	time_begin := time.Now()
	ctx, ctx_cancel := context.WithTimeout(context.Background(), 30*time.Second)

	hosts := make([]*AutonomousHost, N_hosts)
	done_ch := make(chan bool, N_hosts)
	for i := range N_hosts {
		_, privkey, err := ed25519.GenerateKey(crypto_rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		host, host_pathMap, _ := abyss_host.NewBetaAbyssHost(context.Background(), &privkey, nil)

		hosts[i] = &AutonomousHost{
			global_join_targets: global_world_reg,
			abyss_host:          host,
			abyss_pathMap:       host_pathMap,
			log_prefix:          " [" + host.GetLocalAbyssURL().Hash + "] ",
		}
	}
	for i, h := range hosts {
		for j, h_other := range hosts {
			if i == j {
				continue
			}
			h_other_id := h_other.abyss_host.NetworkService.LocalIdentity()
			if h.abyss_host.NetworkService.AppendKnownPeer(h_other_id.RootCertificate(), h_other_id.HandshakeKeyCertificate()) != nil {
				panic("failed to register peer info")
			}
		}
	}
	for _, h := range hosts {
		go h.Run(ctx, time_begin, done_ch)
	}
	for range N_hosts {
		<-done_ch
	}
	ctx_cancel()
}

func assert(statement bool) {
	if !statement {
		panic("assertion failure")
	}
}

func TestObjectSharing(t *testing.T) {
	_, privkey, _ := ed25519.GenerateKey(crypto_rand.Reader)
	hostA, hostA_pathMap, _ := abyss_host.NewBetaAbyssHost(context.Background(), &privkey, nil)
	_, privkey, _ = ed25519.GenerateKey(crypto_rand.Reader)
	hostB, _, _ := abyss_host.NewBetaAbyssHost(context.Background(), &privkey, nil)

	go hostA.ListenAndServe(context.Background())
	go hostB.ListenAndServe(context.Background())

	hostA.NetworkService.AppendKnownPeer(hostB.NetworkService.LocalIdentity().RootCertificate(), hostB.NetworkService.LocalIdentity().HandshakeKeyCertificate())
	hostB.NetworkService.AppendKnownPeer(hostA.NetworkService.LocalIdentity().RootCertificate(), hostA.NetworkService.LocalIdentity().HandshakeKeyCertificate())

	A_world, _ := hostA.OpenWorld("http://a.world.com")
	a_world_ch := A_world.GetEventChannel()
	hostA_pathMap.TrySetMapping("home", A_world.SessionID()) //this opens the world for join from A's side

	<-time.After(100 * time.Millisecond)
	hostA.OpenOutboundConnection(hostB.GetLocalAbyssURL())

	accept_end_ch := make(chan bool, 1)
	go func() {
		(<-a_world_ch).(abyss.EWorldMemberRequest).Accept()
		accept_end_ch <- true
	}()

	join_url := hostA.GetLocalAbyssURL()
	join_url.Path = "home"
	join_ctx, join_ctx_cancel := context.WithTimeout(context.Background(), time.Second)
	B_A_world, err := hostB.JoinWorld(join_ctx, join_url)
	if err != nil {
		t.Fatal(err)
		return
	}
	join_ctx_cancel()
	b_world_ch := B_A_world.GetEventChannel()

	<-accept_end_ch
	(<-b_world_ch).(abyss.EWorldMemberRequest).Accept()

	(<-a_world_ch).(abyss.EWorldMemberReady).Member.AppendObjects([]abyss.ObjectInfo{{ID: uuid.New(), Addr: "carrot.aml"}})
	assert((<-b_world_ch).(abyss.EWorldMemberReady).Member != nil)
	assert((<-b_world_ch).(abyss.EMemberObjectAppend).Objects[0].Addr == "carrot.aml")
}

func TestKnownPeerUpdate(t *testing.T) {
	_, A_privkey, _ := ed25519.GenerateKey(crypto_rand.Reader)
	_, B_privkey, _ := ed25519.GenerateKey(crypto_rand.Reader)
	_, C_privkey, _ := ed25519.GenerateKey(crypto_rand.Reader)

	A_host, _, _ := abyss_host.NewBetaAbyssHost(context.Background(), &A_privkey, nil)
	B_host, B_pathmap, _ := abyss_host.NewBetaAbyssHost(context.Background(), &B_privkey, nil)
	C_host, _, _ := abyss_host.NewBetaAbyssHost(context.Background(), &C_privkey, nil)

	go A_host.ListenAndServe(context.Background())
	go B_host.ListenAndServe(context.Background())
	go C_host.ListenAndServe(context.Background())

	A_host.NetworkService.AppendKnownPeer(
		B_host.NetworkService.LocalIdentity().RootCertificate(),
		B_host.NetworkService.LocalIdentity().HandshakeKeyCertificate(),
	)

	B_host.NetworkService.AppendKnownPeer(
		A_host.NetworkService.LocalIdentity().RootCertificate(),
		A_host.NetworkService.LocalIdentity().HandshakeKeyCertificate(),
	)
	B_host.NetworkService.AppendKnownPeer(
		C_host.NetworkService.LocalIdentity().RootCertificate(),
		C_host.NetworkService.LocalIdentity().HandshakeKeyCertificate(),
	)

	C_host.NetworkService.AppendKnownPeer(
		B_host.NetworkService.LocalIdentity().RootCertificate(),
		B_host.NetworkService.LocalIdentity().HandshakeKeyCertificate(),
	)

	B_world, _ := B_host.OpenWorld("http://b.world.com")
	B_pathmap.TrySetMapping("/home", B_world.SessionID())
	world_aurl := B_host.GetLocalAbyssURL()
	world_aurl.Path = "/home"

	B_host.OpenOutboundConnection(A_host.GetLocalAbyssURL())
	B_host.OpenOutboundConnection(C_host.GetLocalAbyssURL())

	wait_for_A_join := make(chan bool)
	wait_for_A_C_discovery := make(chan bool, 2)
	go func() {
		world, _ := A_host.JoinWorld(context.Background(), world_aurl)
		ev_ch := world.GetEventChannel()
		(<-ev_ch).(abyss.EWorldMemberRequest).Accept()
		assert((<-ev_ch).(abyss.EWorldMemberReady).Member.Hash() == B_host.GetLocalAbyssURL().Hash)

		wait_for_A_join <- true

		(<-ev_ch).(abyss.EWorldMemberRequest).Accept()
		assert((<-ev_ch).(abyss.EWorldMemberReady).Member.Hash() == C_host.GetLocalAbyssURL().Hash)

		wait_for_A_C_discovery <- true
	}()
	go func() {
		<-wait_for_A_join

		world, _ := C_host.JoinWorld(context.Background(), world_aurl)
		ev_ch := world.GetEventChannel()
		(<-ev_ch).(abyss.EWorldMemberRequest).Accept()
		assert((<-ev_ch).(abyss.EWorldMemberReady).Member.Hash() == B_host.GetLocalAbyssURL().Hash)
		(<-ev_ch).(abyss.EWorldMemberRequest).Accept()
		assert((<-ev_ch).(abyss.EWorldMemberReady).Member.Hash() == A_host.GetLocalAbyssURL().Hash)

		wait_for_A_C_discovery <- true
	}()
	ev_ch := B_world.GetEventChannel()
	(<-ev_ch).(abyss.EWorldMemberRequest).Accept()
	assert((<-ev_ch).(abyss.EWorldMemberReady).Member.Hash() == A_host.GetLocalAbyssURL().Hash)
	(<-ev_ch).(abyss.EWorldMemberRequest).Accept()
	assert((<-ev_ch).(abyss.EWorldMemberReady).Member.Hash() == C_host.GetLocalAbyssURL().Hash)

	<-wait_for_A_C_discovery
	<-wait_for_A_C_discovery

	<-time.After(time.Second * 5)
}
