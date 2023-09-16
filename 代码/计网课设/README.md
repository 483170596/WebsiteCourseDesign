```
├──entry/src/main/ets                   // ArkTS代码区
│  ├──common
│  │  ├──bean
│  │  │  ├──NewsData.ets                // 新闻数据
│  │  │  ├──NewsTypeBean.ets            // 新闻类型
│  │  │  └──ResponseResult.ets          // 网络请求数据模型
│  │  ├──constant
│  │  │  └──CommonConstant.ets          // 公共常量类
│  │  └──utils
│  │     ├──HttpUtil.ets                // 网络请求方法
│  │     ├──Logger.ets                  // 日志工具类
│  │     ├──PullDownRefresh.ets         // 下拉刷新方法
│  │     └──PullUpLoadMore.ets          // 上拉加载更多方法
│  ├──entryability
│  │  └──EntryAbility.ts                // 程序入口类
│  ├──pages
│  │  └──Index.ets                      // 主页面
│  ├──view
│  │  ├──CustomRefreshLoadLayout.ets    // 下拉刷新、上拉加载布局文件
│  │  ├──LoadMoreLayout.ets             // 上拉加载布局封装
│  │  ├──NewsItem.ets                   // 新闻数据
│  │  ├──NewsList.ets                   // 新闻列表
│  │  ├──NoMoreLayout.ets               // 上拉停止布局封装
│  │  ├──RefreshLayout.ets              // 下拉刷新布局封装
│  │  └──TabBar.ets                     // 新闻类型页签
│  └──viewmodel
│     └──NewsViewModel.ets              // 新闻ViewModel
├──entry/src/main/resources             // 资源文件目录
└──HttpServerOfNews                     // 服务端代码
```
