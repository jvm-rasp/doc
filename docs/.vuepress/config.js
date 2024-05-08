module.exports = {
    port: "8080",
    dest: "dist",
    base: "/",
    // 是否开启默认预加载js
    shouldPrefetch: (file, type) => {
        return false;
    },
    // webpack 配置 https://vuepress.vuejs.org/zh/config/#chainwebpack
    chainWebpack: config => {
        if (process.env.NODE_ENV === 'production') {
            const dateTime = new Date().getTime();

            // 清除js版本号
            config.output.filename('assets/js/cg-[name].js?v=' + dateTime).end();
            config.output.chunkFilename('assets/js/cg-[name].js?v=' + dateTime).end();

            // 清除css版本号
            config.plugin('mini-css-extract-plugin').use(require('mini-css-extract-plugin'), [{
                filename: 'assets/css/[name].css?v=' + dateTime,
                chunkFilename: 'assets/css/[name].css?v=' + dateTime
            }]).end();

        }
    },
    markdown: {
        lineNumbers: true,
        externalLinks: {
            target: '_blank', rel: 'noopener noreferrer'
        }
    },
    locales: {
        "/": {
            lang: "zh-CN",
            title: "RASP安全技术",
            description: "🔥🔥🔥国内技术领先的开源RASP社区"
        }
    },
    head: [
        // ico
        ['link', {rel: 'icon', href: `/logo.png`}],
        ["meta", {name: "robots", content: "all"}],
        ["meta", {name: "author", content: "patton"}],
        ["meta", {"http-equiv": "Cache-Control", content: "no-cache, no-store, must-revalidate"}],
        ["meta", {"http-equiv": "Pragma", content: "no-cache"}],
        ["meta", {"http-equiv": "Expires", content: "0"}],
        ["meta", {
            name: "keywords",
            content: "rasp,jrasp,字节码编程,jvm,web安全"
        }],
        ["meta", {name: "apple-mobile-web-app-capable", content: "yes"}],
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                // src: 'https://code.jquery.com/jquery-3.5.1.min.js',
                src: '/js/jquery.min.js',
            }],
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                // src: 'https://code.jquery.com/jquery-3.5.1.min.js',
                src: '/js/global.js',
            }],
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                src: '/js/fingerprint2.min.js',
            }],
        ['script',
            {
                charset: 'utf-8',
                async: 'async',
                src: 'https://s9.cnzz.com/z_stat.php?id=1278232949&web_id=1278232949',
            }],
        // 添加百度统计
        ["script", {},
            `
              var _hmt = _hmt || [];
              (function() {
                var hm = document.createElement("script");
                hm.src = "https://hm.baidu.com/hm.js?0b31b4c146bf7126aed5009e1a4a11c8";
                var s = document.getElementsByTagName("script")[0];
                s.parentNode.insertBefore(hm, s);
              })();
            `
        ]
    ],
    plugins: [
        [
            {globalUIComponents: ['LockArticle', 'PayArticle']}
        ],
        // ['@vssue/vuepress-plugin-vssue', {
        //     platform: 'github-v3', //v3的platform是github，v4的是github-v4
        //     // 其他的 Vssue 配置
        //     owner: 'fuzhengwei', //github账户名
        //     repo: 'CodeGuide', //github一个项目的名称
        //     clientId: 'df8beab2190bec20352a',//注册的Client ID
        //     clientSecret: '7eeeb4369d699c933f02a026ae8bb1e2a9c80e90',//注册的Client Secret
        //     autoCreateIssue: true // 自动创建评论，默认是false，最好开启，这样首次进入页面的时候就不用去点击创建评论的按钮了。
        // }
        // ],
        ['@vuepress/back-to-top', true], //replaced with inject page-sidebar
        ['@vuepress/medium-zoom', {
            selector: 'img:not(.nozoom)',
            // See: https://github.com/francoischalifour/medium-zoom#options
            options: {
                margin: 16
            }
        }],
        // https://v1.vuepress.vuejs.org/zh/plugin/official/plugin-pwa.html#%E9%80%89%E9%A1%B9
        // ['@vuepress/pwa', {
        //     serviceWorker: true,
        //     updatePopup: {
        //         '/': {
        //             message: "发现新内容可用",
        //             buttonText: "刷新"
        //         },
        //     }
        // }],
        // see: https://vuepress.github.io/zh/plugins/copyright/#%E5%AE%89%E8%A3%85
        // ['copyright', {
        //     noCopy: false, // 允许复制内容
        //     minLength: 100, // 如果长度超过 100 个字符
        //     authorName: "https://bugstack.cn",
        //     clipboardComponent: "请注明文章出处, [bugstack虫洞栈](https://bugstack.cn)"
        // }],
        // see: https://github.com/ekoeryanto/vuepress-plugin-sitemap
        // ['sitemap', {
        //     hostname: 'https://bugstack.cn'
        // }],
        // see: https://github.com/IOriens/vuepress-plugin-baidu-autopush
        ['vuepress-plugin-baidu-autopush', {}],
        // see: https://github.com/znicholasbrown/vuepress-plugin-code-copy
        ['vuepress-plugin-code-copy', {
            align: 'bottom',
            color: '#3eaf7c',
            successText: '@RASP安全技术: 代码已经复制到剪贴板'
        }],
        // see: https://github.com/tolking/vuepress-plugin-img-lazy
        ['img-lazy', {}],
        ["vuepress-plugin-tags", {
            type: 'default', // 标签预定义样式
            color: '#42b983',  // 标签字体颜色
            border: '1px solid #e2faef', // 标签边框颜色
            backgroundColor: '#f0faf5', // 标签背景颜色
            selector: '.page .content__default h1' // ^v1.0.1 你要将此标签渲染挂载到哪个元素后面？默认是第一个 H1 标签后面；
        }],
        // https://github.com/lorisleiva/vuepress-plugin-seo
        ["seo", {
            siteTitle: (_, $site) => $site.title,
            title: $page => $page.title,
            description: $page => $page.frontmatter.description,
            author: (_, $site) => $site.themeConfig.author,
            tags: $page => $page.frontmatter.tags,
            // twitterCard: _ => 'summary_large_image',
            type: $page => 'article',
            url: (_, $site, path) => ($site.themeConfig.domain || '') + path,
            image: ($page, $site) => $page.frontmatter.image && (($site.themeConfig.domain && !$page.frontmatter.image.startsWith('http') || '') + $page.frontmatter.image),
            publishedAt: $page => $page.frontmatter.date && new Date($page.frontmatter.date),
            modifiedAt: $page => $page.lastUpdated && new Date($page.lastUpdated),
        }]
    ],
    themeConfig: {
        docsRepo: "jvm-rasp/CodeGuide",
        // 编辑文档的所在目录
        docsDir: 'docs',
        // 文档放在一个特定的分支下：
        docsBranch: 'master',
        //logo: "/logo.png",
        editLinks: true,
        sidebarDepth: 0,
        //smoothScroll: true,
        locales: {
            "/": {
                label: "简体中文",
                selectText: "Languages",
                editLinkText: "在 GitHub 上编辑此页",
                lastUpdated: "上次更新",
                nav: require('./nav/zh'),
                sidebar: {
                    '/guide/': getGuideSidebar('概述', '安装', '深入', '案例', 'FAQ', '故障'),
                    '/case/': getCaseSidebar('命令执行', '表达式注入', '反序列化', 'SQL注入', '文件访问', '外部实体注入'),
                    '/algorithm/': getAlgorithmSidebar('命令执行', 'SQL注入', 'XXE', '线程注入'),
                    '/book/': getBookSidebar('本书序言与推荐', '第一章背景介绍', '第二章字节码指令简介', '第三章Attach技术', '第四章类加载器',
                        '第五章线程变量', '第六章Java Agent', '第七章性能诊断工具',
                        '第八章RASP实现原理', '第九章命令执行', '第十章表达式执行'
                    )
                }
            }
        }
    }
};

function getGuideSidebar(groupA, groupB, groupC, groupE, groupF, groupG) {
    return [
        {
            title: groupA,
            collapsable: false,
            children: [
                '',
                'product/features'
            ]
        },
        {
            title: groupB,
            collapsable: false,
            children: [
                'install/v1.2.0/jrasp-agent',
                'install/v1.1.3/jrasp-agent',
                //'install/v1.1.2/jrasp-agent',
                'install/v1.1.3/install-all',
                'install/v1.1.3/create_config',
                'example/example'
            ]
        },
        {
            title: groupC,
            collapsable: false,
            children: [
                'technology/design',
                'technology/changelog',
                'technology/runtime-mode',
                'technology/hotupdate',
                'technology/native_method',
                'technology/memory_leak',
                'technology/reflect'
            ]
        },
        {
            title: groupE,
            collapsable: false,
            children: [
                'case/jpress',
                'case/case20230619/case20230619',
                'case/case20230902/case20230902'
            ]
        },
        {
            title: groupF,
            collapsable: false,
            children: [
                'faq/faq',
            ]
        },
        {
            title: groupG,
            collapsable: false,
            children: [
                'coe/nacos_crash',
            ]
        }
    ]
}

function getCaseSidebar(groupA, groupB, groupC, groupD, groupE, groupF) {
    return [
        // 命令执行
        {
            title: groupA,
            collapsable: true,
            children: [
                //'RCE',
                'CVE-2022-42889',
                'CVE-2022-33891',
                'CVE-2022-22965',
                'CVE-2022-22947',
                'CVE-2021-25646',
                'CVE-2021-29505',
                'CVE-2020-17530',
                'CVE-2020-14882',
                'CVE-2020-13942',
                'SpringBootActuatorH2',
                'CVE-2019-17558',
                'CVE-2019-0193',
                'CVE-2018-1273',
                'CVE-2018-1270',
                'CVE-2017-12629',
                'CVE-2017-8046',
                'CVE-2016-3088',
            ]
        },
        // 表达式注入
        {
            title: groupB,
            collapsable: true,
            children: [
                'Spring-Cloud-Function-spel',
                'CVE-2020-13942',
                'CVE-2017-7525'
            ]
        },
        // 反序列化
        {
            title: groupC,
            collapsable: true,
            children: [
                'CVE-2021-35464',
                'CVE-2020-36188',
                'CVE-2020-35728',
                'CVE-2021-26295',
                'CVE-2020-9484',
                'CVE-2019-17571',
                'CVE-2019-12384',
                'CVE-2016-4437',
            ]
        },
        // SQL注入
        {
            title: groupD,
            collapsable: true,
            children: []
        },
        // 文件访问
        {
            title: groupE,
            collapsable: true,
            children: [
                'CVE-2021-34429',
                'CVE-2021-28164',
                'CVE-2021-21234',
                'ApacheSolr',
                'CVE-2020-26259',
                'CVE-2020-17519',
                'CVE-2020-5410',
                'CVE-2020-1938'
            ]
        },
        // XXE
        {
            title: groupF,
            collapsable: true,
            children: [
                //'XXE',
                'CVE-2018-15531',
                'CVE-2018-1259'
            ]
        }
    ]
}

function getBookSidebar(group0, groupA, groupA1, groupB, groupC, groupD, groupE, groupF, groupG, groupH, groupH2) {
    return [
        {
            title: group0,
            collapsable: false,
            children: [
                'recommendation/0',
            ]
        },
        {
            title: groupA,
            collapsable: false,
            children: [
                'preface/1',
            ]
        },
        {
            title: groupA1,
            collapsable: false,
            children: []
        },
        {
            title: groupB,
            collapsable: false,
            children: [
                'attach/0',
                'attach/1',
                'attach/2',
                'attach/3',
                'attach/4',
            ]
        },
        {
            title: groupC,
            collapsable: false,
            children: [
                'classloader/0',
                'classloader/1',
                'classloader/2',
                'classloader/3',
                'classloader/4',
                'classloader/5',
                'classloader/6',
            ]
        },
        {
            title: groupD,
            collapsable: false,
            children: [
                'threadlocal/0',
                'threadlocal/1',
                'threadlocal/2',
                'threadlocal/3',
                'threadlocal/4',
            ]
        },
        {
            title: groupE,
            collapsable: false,
            children: [
                'javaagent/0',
                'javaagent/1',
                'javaagent/2'
            ]
        },
        {
            title: groupF,
            collapsable: false,
            children: [
                'tools/0',
                'tools/1',
                'tools/2',
                'tools/3',
                'tools/4',
                'tools/5',
                'tools/6',
                'tools/7',
                'tools/8',
            ]
        },
        {
            title: groupG,
            collapsable: false,
            children: []
        },
        {
            title: groupH,
            collapsable: false,
            children: [
                'rce/0',
                'rce/1',
                'rce/2',
                'rce/3',
                'rce/4',
            ]
        },
        {
            title: groupH2,
            collapsable: false,
            children: [
                'expression/0',
                'expression/1',
                'expression/2',
                'expression/3',
                'expression/4',
            ]
        },
        {
            title: '第十一章内存马',
            collapsable: false,
            children: [
                'shell/0',
                'shell/1',
                'shell/2',
                'shell/3',
                'shell/4',
            ]
        },
        {
            title: '第十二章文件访问',
            collapsable: false,
            children: [
                'file/0',
                'file/1',
                'file/2',
                'file/3',
                'file/4',
            ]
        },
        {
            title: '第十三章SQL 注入',
            collapsable: false,
            children: [
                'sql/0',
                'sql/1',
                'sql/2',
                'sql/3',
                'sql/4',
            ]
        },
        {
            title: '第十四章外部实体注入XXE',
            collapsable: false,
            children: [
                'xxe/0',
                'xxe/1',
                'xxe/2',
                'xxe/3',
                'xxe/4',
            ]
        },
        {
            title: '第十五章服务端请求伪造SSRF',
            collapsable: false,
            children: [
                'ssrf/0',
                'ssrf/1',
                'ssrf/2',
                'ssrf/3',
                'ssrf/4',
            ]
        },
        {
            title: '第十六章反序列化',
            collapsable: false,
            children: [
                'deserialization/0',
                'deserialization/1',
                'deserialization/2',
                'deserialization/3',
                'deserialization/4',
                'deserialization/5',
            ]
        }
        ,
        {
            title: '第十七章HTTP请求',
            collapsable: false,
            children: [
                'http/0',
                'http/1',
                'http/2',
                'http/3',
                'http/4',
            ]
        }
    ]
}

function getAlgorithmSidebar(groupA, groupB, groupC, groupD) {
    return [
        // rce
        {
            title: groupA,
            collapsable: true,
            children: [
                'rce/rce-basic-principles',
                'rce/rce-algorithm',
            ]
        },
        // sql inject
        {
            title: groupB,
            collapsable: true,
            children: [
                'sql/mysql'
            ]
        },
        // xxe
        {
            title: groupC,
            collapsable: true,
            children: [
                'xxe/xxe'
            ]
        },
        // thread
        {
            title: groupD,
            collapsable: true,
            children: [
                'thread/thread_inject'
            ]
        }
    ]
}