package handler

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/olekukonko/tablewriter"
	"github.com/xlab/treeprint"

	"github.com/jumpserver/koko/pkg/cctx"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/i18n"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/model"
	"github.com/jumpserver/koko/pkg/proxy"
	"github.com/jumpserver/koko/pkg/service"
	"github.com/jumpserver/koko/pkg/utils"
)

func SessionHandler(sess ssh.Session) {
	options := parseSessionEnvironment(sess)
	interactive := true
	value, ok := options["Interactive"]
	if ok {
		interactive = value != "no"
	}

	var pty ssh.Pty
	if interactive {
		pty, _, ok = sess.Pty()
		if !ok {
			utils.IgnoreErrWriteString(sess, "Pty must be requested for interactive mode")
			return
		}
	}

	ctx, cancel := cctx.NewContext(sess)
	defer cancel()
	handler := newHandler(sess, ctx.User(), interactive)

	if interactive {
		logger.Infof("Request %s: User %s request pty %s", handler.sess.ID(), sess.User(), pty.Term)
		handler.DispatchInteractive(ctx)
	} else {
		logger.Infof("Request %s: User %s doesn't request pty", handler.sess.ID(), sess.User())
		asset, su := getAssetAndSystemUserForNoInteractiveMode(sess, ctx.User(), options)
		handler.DispatchNonInteractive(ctx, asset, su)
	}
}

func newHandler(sess ssh.Session, user *model.User, interactive bool) *handler {
	wrapperSess := NewWrapperSession(sess, interactive)
	handler := &handler{
		sess:        wrapperSess,
		user:        user,
		interactive: interactive,
	}
	if interactive {
		handler.term = utils.NewTerminal(wrapperSess, "Opt> ")
	}
	handler.Initial()
	return handler
}

type handler struct {
	sess        *WrapperSession
	user        *model.User
	interactive bool

	term         *utils.Terminal
	winWatchChan chan bool

	assetSelect      *model.Asset
	systemUserSelect *model.SystemUser
	nodes            model.NodeList
	searchResult     []model.Asset

	allAssets []model.Asset
	search    string
	offset    int
	limit     int

	loadDataDone    chan struct{}
	assetLoadPolicy string
}

func (h *handler) Initial() {
	h.assetLoadPolicy = strings.ToLower(config.GetConf().AssetLoadPolicy)
	if h.interactive {
		h.displayBanner()
		h.winWatchChan = make(chan bool)
	}
	h.loadDataDone = make(chan struct{})
	go h.firstLoadData()
}

func (h *handler) firstLoadData() {
	h.loadUserNodes("1")
	switch h.assetLoadPolicy {
	case "all":
		h.loadAllAssets()
	}
	close(h.loadDataDone)
}

func (h *handler) displayBanner() {
	displayBanner(h.sess, h.user.Name)
}

func (h *handler) watchWinSizeChange() {
	sessChan := h.sess.WinCh()
	winChan := sessChan
	defer logger.Infof("Request %s: Windows change watch close", h.sess.Uuid)
	for {
		select {
		case <-h.sess.Sess.Context().Done():
			return
		case sig, ok := <-h.winWatchChan:
			if !ok {
				return
			}
			switch sig {
			case false:
				winChan = nil
			case true:
				winChan = sessChan
			}
		case win, ok := <-winChan:
			if !ok {
				return
			}
			logger.Debugf("Term window size change: %d*%d", win.Height, win.Width)
			_ = h.term.SetSize(win.Width, win.Height)
		}
	}
}

func (h *handler) pauseWatchWinSize() {
	h.winWatchChan <- false
}

func (h *handler) resumeWatchWinSize() {
	h.winWatchChan <- true
}

func (h *handler) DispatchInteractive(ctx cctx.Context) {
	go h.watchWinSizeChange()
	defer logger.Infof("Request %s: User %s stop interactive", h.sess.ID(), h.user.Name)

	for {
		line, err := h.term.ReadLine()
		if err != nil {
			logger.Debugf("User %s close connect", h.user.Name)
			break
		}
		line = strings.TrimSpace(line)
		switch len(line) {
		case 0, 1:
			switch strings.ToLower(line) {
			case "", "p":
				// 展示所有的资产
				h.displayAllAssets()
			case "g":
				<-h.loadDataDone
				h.displayNodes(h.nodes)
			case "h":
				h.displayBanner()
			case "r":
				h.refreshAssetsAndNodesData()
			case "q":
				logger.Debugf("user %s enter to exit", h.user.Name)
				return
			default:
				h.searchAssetOrProxy(line)
			}
		default:
			switch {
			case line == "exit", line == "quit":
				logger.Debugf("user %s enter to exit", h.user.Name)
				return
			case strings.Index(line, "/") == 0:
				searchWord := strings.TrimSpace(line[1:])
				h.searchAsset(searchWord)
			case strings.Index(line, "g") == 0:
				searchWord := strings.TrimSpace(strings.TrimPrefix(line, "g"))
				if num, err := strconv.Atoi(searchWord); err == nil {
					if num >= 0 {
						assets := h.searchNodeAssets(num)
						h.displayAssets(assets)
						continue
					}
				}
				h.searchAssetOrProxy(line)
			default:
				h.searchAssetOrProxy(line)
			}
		}

	}
}

func (h *handler) DispatchNonInteractive(ctx cctx.Context, asset *model.Asset, su *model.SystemUser) {
	h.assetSelect = asset
	h.systemUserSelect = su
	defer logger.Infof("Request %s: User %s stopped", h.sess.ID(), h.user.Name)
	h.Proxy(context.Background())
}

func (h *handler) displayAllAssets() {
	switch h.assetLoadPolicy {
	case "all":
		<-h.loadDataDone
		h.displayAssets(h.allAssets)
	default:
		pag := NewUserPagination(h.term, h.user.ID, "", false)
		result := pag.Start()
		if pag.IsNeedProxy && len(result) == 1 {
			h.searchResult = h.searchResult[:0]
			h.ProxyAsset(result[0])
		} else {
			h.searchResult = result
		}
	}
}

func (h *handler) chooseSystemUser(systemUsers []model.SystemUser) model.SystemUser {
	length := len(systemUsers)
	switch length {
	case 0:
		return model.SystemUser{}
	case 1:
		return systemUsers[0]
	default:
	}
	displaySystemUsers := selectHighestPrioritySystemUsers(systemUsers)
	if len(displaySystemUsers) == 1 {
		return displaySystemUsers[0]
	}

	table := tablewriter.NewWriter(h.term)
	table.SetHeader([]string{"ID", "Name"})
	for i := 0; i < len(displaySystemUsers); i++ {
		table.Append([]string{strconv.Itoa(i + 1), displaySystemUsers[i].Name})
	}
	table.SetBorder(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	h.term.SetPrompt("ID> ")
	defer h.term.SetPrompt("Opt> ")
	for count := 0; count < 3; count++ {
		table.Render()
		line, err := h.term.ReadLine()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if num, err := strconv.Atoi(line); err == nil {
			if num > 0 && num <= len(displaySystemUsers) {
				return displaySystemUsers[num-1]
			}
		}
	}
	return displaySystemUsers[0]
}

func (h *handler) displayAssets(assets model.AssetList) {
	if len(assets) == 0 {
		_, _ = io.WriteString(h.term, i18n.T("No Assets")+"\n\r")
	} else {
		sortedAssets := assets.SortBy(config.GetConf().AssetListSortBy)
		pag := NewAssetPagination(h.term, sortedAssets)
		selectOneAssets := pag.Start()
		if len(selectOneAssets) == 1 {
			systemUsers := service.GetUserAssetSystemUsers(h.user.ID, selectOneAssets[0].ID)
			systemUser := h.chooseSystemUser(systemUsers)
			h.assetSelect = &selectOneAssets[0]
			h.systemUserSelect = &systemUser
			h.Proxy(context.TODO())
		}
		if pag.page.PageSize() >= pag.page.TotalCount() {
			h.searchResult = sortedAssets
		}
	}
}

func (h *handler) displayNodes(nodes []model.Node) {
	tree := ConstructAssetNodeTree(nodes)
	tipHeaderMsg := i18n.T("Node: [ ID.Name(Asset amount) ]")
	tipEndMsg := i18n.T("Tips: Enter g+NodeID to display the host under the node, such as g1")

	_, err := io.WriteString(h.term, "\n\r"+tipHeaderMsg)
	_, err = io.WriteString(h.term, tree.String())
	_, err = io.WriteString(h.term, tipEndMsg+"\n\r")
	if err != nil {
		logger.Info("displayAssetNodes err:", err)
	}

}

func (h *handler) refreshAssetsAndNodesData() {
	switch h.assetLoadPolicy {
	case "all":
		h.loadAllAssets()
	}
	h.loadUserNodes("2")
	_, err := io.WriteString(h.term, i18n.T("Refresh done")+"\n\r")
	if err != nil {
		logger.Error("refresh Assets  Nodes err:", err)
	}
}

func (h *handler) loadUserNodes(cachePolicy string) {
	h.nodes = service.GetUserNodes(h.user.ID, cachePolicy)
}

func (h *handler) loadAllAssets() {
	h.allAssets = service.GetUserAllAssets(h.user.ID)
}

func (h *handler) searchAsset(key string) {
	switch h.assetLoadPolicy {
	case "all":
		<-h.loadDataDone
		var searchData []model.Asset
		switch len(h.searchResult) {
		case 0:
			searchData = h.allAssets
		default:
			searchData = h.searchResult
		}
		assets := searchFromLocalAssets(searchData, key)
		h.displayAssets(assets)
	default:
		pag := NewUserPagination(h.term, h.user.ID, key, false)
		result := pag.Start()
		if pag.IsNeedProxy && len(result) == 1 {
			h.searchResult = h.searchResult[:0]
			h.ProxyAsset(result[0])
		} else {
			h.searchResult = result
		}
	}
}

func (h *handler) searchAssetOrProxy(key string) {
	if indexNum, err := strconv.Atoi(key); err == nil && len(h.searchResult) > 0 {
		if indexNum > 0 && indexNum <= len(h.searchResult) {
			assetSelect := h.searchResult[indexNum-1]
			h.ProxyAsset(assetSelect)
			return
		}
	}
	var assets []model.Asset
	switch h.assetLoadPolicy {
	case "all":
		<-h.loadDataDone
		var searchData []model.Asset
		switch len(h.searchResult) {
		case 0:
			searchData = h.allAssets
		default:
			searchData = h.searchResult
		}
		assets = searchFromLocalAssets(searchData, key)
		if len(assets) != 1 {
			h.displayAssets(assets)
			return
		}
	default:
		pag := NewUserPagination(h.term, h.user.ID, key, true)
		assets = pag.Start()
	}

	if len(assets) == 1 {
		h.ProxyAsset(assets[0])
	} else {
		h.searchResult = assets
	}
}

func (h *handler) searchNodeAssets(num int) (assets model.AssetList) {
	if num > len(h.nodes) || num == 0 {
		return assets
	}
	node := h.nodes[num-1]
	assets = service.GetUserNodeAssets(h.user.ID, node.ID, "1")
	return
}

func (h *handler) ProxyAsset(assetSelect model.Asset) {
	systemUsers := service.GetUserAssetSystemUsers(h.user.ID, assetSelect.ID)
	systemUserSelect := h.chooseSystemUser(systemUsers)
	h.systemUserSelect = &systemUserSelect
	h.assetSelect = &assetSelect
	h.Proxy(context.Background())
}

func (h *handler) Proxy(ctx context.Context) {
	p := proxy.ProxyServer{
		UserConn:   h.sess,
		User:       h.user,
		Asset:      h.assetSelect,
		SystemUser: h.systemUserSelect,
	}
	if h.interactive {
		h.pauseWatchWinSize()
		p.Proxy()
		h.resumeWatchWinSize()
	} else {
		p.Proxy()
	}
}

func ConstructAssetNodeTree(assetNodes []model.Node) treeprint.Tree {
	model.SortAssetNodesByKey(assetNodes)
	var treeMap = map[string]treeprint.Tree{}
	tree := treeprint.New()
	for i := 0; i < len(assetNodes); i++ {
		r := strings.LastIndex(assetNodes[i].Key, ":")
		if r < 0 {
			subtree := tree.AddBranch(fmt.Sprintf("%s.%s(%s)",
				strconv.Itoa(i+1), assetNodes[i].Name,
				strconv.Itoa(assetNodes[i].AssetsAmount)))
			treeMap[assetNodes[i].Key] = subtree
			continue
		}
		if _, ok := treeMap[assetNodes[i].Key[:r]]; !ok {
			subtree := tree.AddBranch(fmt.Sprintf("%s.%s(%s)",
				strconv.Itoa(i+1), assetNodes[i].Name,
				strconv.Itoa(assetNodes[i].AssetsAmount)))
			treeMap[assetNodes[i].Key] = subtree
			continue
		}
		if subtree, ok := treeMap[assetNodes[i].Key[:r]]; ok {
			nodeTree := subtree.AddBranch(fmt.Sprintf("%s.%s(%s)",
				strconv.Itoa(i+1), assetNodes[i].Name,
				strconv.Itoa(assetNodes[i].AssetsAmount)))
			treeMap[assetNodes[i].Key] = nodeTree
		}
	}
	return tree
}

func isSubstring(sArray []string, substr string) bool {
	for _, s := range sArray {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func selectHighestPrioritySystemUsers(systemUsers []model.SystemUser) []model.SystemUser {
	length := len(systemUsers)
	if length == 0 {
		return systemUsers
	}
	var result = make([]model.SystemUser, 0)
	model.SortSystemUserByPriority(systemUsers)

	highestPriority := systemUsers[length-1].Priority

	result = append(result, systemUsers[length-1])
	for i := length - 2; i >= 0; i-- {
		if highestPriority == systemUsers[i].Priority {
			result = append(result, systemUsers[i])
		}
	}
	return result
}

func searchFromLocalAssets(assets model.AssetList, key string) []model.Asset {
	displayAssets := make([]model.Asset, 0, len(assets))
	key = strings.ToLower(key)
	for _, assetValue := range assets {
		contents := []string{strings.ToLower(assetValue.Hostname),
			strings.ToLower(assetValue.IP), strings.ToLower(assetValue.Comment)}
		if isSubstring(contents, key) {
			displayAssets = append(displayAssets, assetValue)
		}
	}
	return displayAssets
}
