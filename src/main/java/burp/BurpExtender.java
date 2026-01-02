package burp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.List;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IScannerCheck, IMessageEditorController, IContextMenuFactory {

    String version = "1.5";
    private final List<LogEntry> log_raw = new ArrayList<LogEntry>();//记录原始流量
    private final List<LogEntry> log2 = new ArrayList<LogEntry>();//记录攻击流量
    private final List<LogEntry> log_show = new ArrayList<LogEntry>();//用于展现
    private final List<Request_md5> log_md5 = new ArrayList<Request_md5>();//用于存放数据包的md5
    public PrintWriter stdout;
    public AbstractTableModel model = new log_show_Model();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;

    Table logTable; //第一个表格框
    int switchs = 1; //开关 0关 1开
    int clicks_Repeater = 0;//64是监听 0是关闭
    int clicks_Proxy = 0;//4是监听 0是关闭
    int conut = 0; //记录条数
    String data_md5_id; //用于判断目前选中的数据包
    int original_data_len;//记录原始数据包的长度

    boolean is_mybatis = true; //mybatis型开关
    int is_cookie = -1;//cookie型开关
    boolean is_debug = false;//debug开关
    boolean is_sleep = false;//sleep开关
    int sleep_time = 500;
    boolean is_noscan_page = true;//noscan_page开关
    boolean is_add_order = true;//add_order开关
    boolean is_Zpayload = false;//自定义payload开关
    String static_file = "jpg,jpeg,png,gif,ico,css,js,svg,pdf,mp3,mp4,avi,ttf,woff,woff2";
    String[] static_file_list;
    String page_str = "page,pages,pageno,pageindex,pagesize,pagenum,rows,size";
    String[] page_list;
    String order_str = "order,orderBy,groupBy,sort,sortBy,desc,asc,table,column";
    String[] order_list;
    String payload_str = "";
    String[] payload_list;

    String temp_data; //用于保存临时内容
    int select_row = 0;//选中表格的行数
    String white_URL = "";
    int white_switchs = 0;//白名单开关

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello XG_SQL!");
        this.stdout.println("你好 小刚SQL!");
        this.stdout.println("version: " + version);

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("XG_SQL " + version);

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {

                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                splitPane.setDividerLocation(1200);//设置分割的大小
                JSplitPane splitPanes_left = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JSplitPane splitPanes_rigth = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                //左上角
                JPanel jp_l_up= new JPanel(new GridLayout(1, 2, 5, 5));
                logTable = new Table(BurpExtender.this);
                JScrollPane logTable_l = new JScrollPane(logTable);
                Table_log2 table = new Table_log2(model);
                JScrollPane logTable_r = new JScrollPane(table);
                jp_l_up.add(logTable_l);
                jp_l_up.add(logTable_r);

                //左下角
                JSplitPane jp_l_down = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                jp_l_down.setLeftComponent(requestViewer.getComponent());
                jp_l_down.setRightComponent(responseViewer.getComponent());
                jp_l_down.setDividerLocation(600);

                //右边
                JPanel jp_r_up = new JPanel();
                jp_r_up.setLayout(new GridLayout(20, 1));
                JLabel jl_author = new JLabel("插件名: XG_SQL  原作者: 算命縖子  二开: XG小刚");
                JLabel jl_version = new JLabel("版本: XG_SQL " + version);
                JCheckBox chkbox_start = new JCheckBox("启动插件", true);
                JCheckBox chkbox_Repeater = new JCheckBox("监控Repeater");
                JCheckBox chkbox_Proxy = new JCheckBox("监控Proxy");
                JCheckBox chkbox_cookie = new JCheckBox("Cookie型检测",false);
                JCheckBox chkbox_mybatis = new JCheckBox("MyBatis型检测", true);
                JCheckBox chkbox_debug = new JCheckBox("debug输出", false);
                JCheckBox chkbox_sleep = new JCheckBox("放缓请求速度Thread.sleep("+sleep_time+")", false);
                JCheckBox chkbox_page = new JCheckBox("noscan_page跳过参数", true);
                JTextField textField_page = new JTextField(page_str);
                JCheckBox chkbox_addorder = new JCheckBox("add_order增加参数", true);
                JTextField textField_addorder = new JTextField(order_str);
                JButton btn_clean = new JButton("清空列表");

                JLabel jl_white = new JLabel("如果需要多个域名加白请用,隔开");
                JTextField textField_white = new JTextField("填写白名单域名");
                JButton btn_white = new JButton("启动白名单");

                JLabel jl_ini = new JLabel("修改配置保存后生效");
                JPanel jp_ini = new JPanel();
                jp_ini.setLayout(new GridLayout(1, 3));
                JButton btn_saveini = new JButton("保存配置");
                JButton btn_loadini = new JButton("加载配置");
                JButton btn_resetini = new JButton("重置配置");
                jp_ini.add(btn_saveini);
                jp_ini.add(btn_loadini);
                jp_ini.add(btn_resetini);

                JCheckBox chkbox_payload = new JCheckBox("自定义payload");
                JPanel jp_payload = new JPanel();
                jp_payload.setLayout(new GridLayout(1, 1));
                String payload_str = "' and sleep(5) = '1";
                JTextArea textArea_payload = new JTextArea(payload_str, 18, 16);

                static_file_list = static_file.split(",");
                page_list = textField_page.getText().split(",");
                order_list = textField_addorder.getText().split(",");

                //读取ini配置文件
                try {
                    Properties p = new Properties();
                    FileInputStream inifile = new FileInputStream("XgSql_config.ini");
                    p.load(inifile);
                    String pages = p.getProperty("pages");
                    String order = p.getProperty("order");
                    String payload = p.getProperty("payload");
                    try {
                        pages = new String(java.util.Base64.getDecoder().decode(pages));
                        order = new String(java.util.Base64.getDecoder().decode(order));
                        payload = new String(java.util.Base64.getDecoder().decode(payload));
                        textField_page.setText(pages);
                        textField_addorder.setText(order);
                        textArea_payload.setText(payload);
                    }catch (Exception e){
                        textField_page.setText("");
                        textField_addorder.setText("");
                        textArea_payload.setText("");
                    }
                    page_list = pages.split(",");
                    order_list = order.split(",");
                    payload_list = payload.split("\n");
                    inifile.close();
                } catch (IOException exception) {
                }

                textArea_payload.setForeground(Color.BLACK);    //设置组件的背景色
                textArea_payload.setFont(new Font("楷体", Font.BOLD, 16));    //修改字体样式
                textArea_payload.setBackground(Color.LIGHT_GRAY);    //设置背景色
                textArea_payload.setEditable(false);//不可编辑状态
                JScrollPane jsp = new JScrollPane(textArea_payload);    //将文本域放入滚动窗口
                jp_payload.add(jsp);    //将JScrollPane添加到JPanel容器中

                jp_r_up.add(jl_author);
                jp_r_up.add(jl_version);
                jp_r_up.add(chkbox_start);
                jp_r_up.add(chkbox_Repeater);
                jp_r_up.add(chkbox_Proxy);
                jp_r_up.add(chkbox_mybatis);
                jp_r_up.add(chkbox_cookie);
                jp_r_up.add(chkbox_debug);
                jp_r_up.add(chkbox_sleep);
                jp_r_up.add(chkbox_page);
                jp_r_up.add(textField_page);
                jp_r_up.add(chkbox_addorder);
                jp_r_up.add(textField_addorder);
                jp_r_up.add(btn_clean);
                jp_r_up.add(jl_white);
                jp_r_up.add(textField_white);
                jp_r_up.add(btn_white);
                jp_r_up.add(jl_ini);
                jp_r_up.add(jp_ini);
                jp_r_up.add(chkbox_payload);

                //添加复选框监听事件
                chkbox_start.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_start.isSelected()) {
                            stdout.println("插件XG_SQL启动");
                            switchs = 1;
                        } else {
                            stdout.println("插件XG_SQL关闭");
                            switchs = 0;
                        }
                    }
                });
                chkbox_Repeater.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_Repeater.isSelected()) {
                            stdout.println("启动 监控Repeater");
                            clicks_Repeater = 64;
                        } else {
                            stdout.println("关闭 监控Repeater");
                            clicks_Repeater = 0;
                        }
                    }
                });
                chkbox_Proxy.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_Proxy.isSelected()) {
                            stdout.println("启动 监控Proxy");
                            clicks_Proxy = 4;
                        } else {
                            stdout.println("关闭 监控Proxy");
                            clicks_Proxy = 0;
                        }
                    }
                });
                chkbox_mybatis.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_mybatis.isSelected()) {
                            stdout.println("启动 mybaties型检测");
                            is_mybatis = true;
                        } else {
                            stdout.println("关闭 mybaties型检测");
                            is_mybatis = false;
                        }
                    }
                });
                chkbox_cookie.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_cookie.isSelected()) {
                            stdout.println("启动 Cookie型测试");
                            is_cookie = 2;
                        } else {
                            stdout.println("关闭 Cookie型测试");
                            is_cookie = -1;
                        }
                    }
                });
                chkbox_debug.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_debug.isSelected()) {
                            stdout.println("启动 debug");
                            is_debug = true;
                        } else {
                            stdout.println("关闭 debug");
                            is_debug = false;
                        }
                    }
                });
                chkbox_sleep.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_sleep.isSelected()) {
                            stdout.println("启动 Thread.sleep(500)");
                            is_sleep = true;
                        } else {
                            stdout.println("关闭 Thread.sleep(500)");
                            is_sleep = false;
                        }
                    }
                });
                chkbox_page.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_page.isSelected()) {
                            stdout.println("开启 noscan_page");
                            is_noscan_page = true;
                        } else {
                            stdout.println("关闭 noscan_page");
                            is_noscan_page = false;
                        }
                    }
                });
                chkbox_addorder.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_addorder.isSelected()) {
                            stdout.println("开启 add_order");
                            is_add_order = true;
                        } else {
                            stdout.println("关闭 add_order");
                            is_add_order = false;
                        }
                    }
                });
                chkbox_payload.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox_payload.isSelected()) {
                            stdout.println("启动 自定义payload");
                            textArea_payload.setEditable(true);
                            textArea_payload.setBackground(Color.WHITE);
                            is_Zpayload = true;
                            String payload = textArea_payload.getText();
                            payload_list = payload.split("\n");
                        } else {
                            stdout.println("关闭 自定义payload");
                            textArea_payload.setEditable(false);
                            textArea_payload.setBackground(Color.LIGHT_GRAY);
                            is_Zpayload = false;
                        }
                    }
                });
                btn_clean.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log_raw.clear();//清除log_raw的内容
                        log2.clear();//清除log2的内容
                        log_show.clear();//清除log_show的内容
                        log_md5.clear();//清除log_md5的内容
                        conut = 0;
                        fireTableRowsInserted(log_raw.size(), log_raw.size());//刷新列表中的展示
                        model.fireTableRowsInserted(log_show.size(), log_show.size());//刷新列表中的展示
                    }
                });
                btn_white.addActionListener(new ActionListener() {//白名单
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (btn_white.getText().equals("启动白名单")) {
                            btn_white.setText("关闭白名单");
                            white_URL = textField_white.getText();
                            white_switchs = 1;
                            textField_white.setEditable(false);
                            textField_white.setForeground(Color.GRAY);
                        } else {
                            btn_white.setText("启动白名单");
                            white_switchs = 0;
                            textField_white.setEditable(true);
                            textField_white.setForeground(Color.BLACK);
                        }
                    }
                });
                btn_saveini.addActionListener(new ActionListener() {//save配置
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String diy_ini="";
                        String pages = textField_page.getText();
                        String order = textField_addorder.getText();
                        String payload = textArea_payload.getText();
                        diy_ini += "pages = " + java.util.Base64.getEncoder().encodeToString(pages.getBytes(StandardCharsets.UTF_8)) + "\n";
                        diy_ini += "order = " + java.util.Base64.getEncoder().encodeToString(order.getBytes(StandardCharsets.UTF_8)) + "\n";
                        diy_ini += "payload = " + java.util.Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "\n";
                        try {
                            BufferedWriter out = new BufferedWriter(new FileWriter("XgSql_config.ini"));
                            out.write(diy_ini);
                            out.close();
                        } catch (IOException exception) {
                        }
                        page_list = pages.split(",");
                        order_list = order.split(",");
                        payload_list = payload.split("\n");
                    }
                });
                btn_loadini.addActionListener(new ActionListener() {//load配置
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        try {
                            Properties p = new Properties();
                            FileInputStream inifile = new FileInputStream("XgSql_config.ini");
                            p.load(inifile);
                            String pages = new String(java.util.Base64.getDecoder().decode(p.getProperty("pages")));
                            String order = new String(java.util.Base64.getDecoder().decode(p.getProperty("order")));
                            String payload = new String(java.util.Base64.getDecoder().decode(p.getProperty("payload")));

                            textField_page.setText(pages);
                            textField_addorder.setText(order);
                            textArea_payload.setText(payload);
                            inifile.close();

                            page_list = pages.split(",");
                            order_list = order.split(",");
                            payload_list = payload.split("\n");
                        } catch (IOException exception) {
                        }
                    }
                });
                btn_resetini.addActionListener(new ActionListener() {//reset配置
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        textField_page.setText(page_str);
                        textField_addorder.setText(order_str);
                        textArea_payload.setText(payload_str);

                        page_list = page_str.split(",");
                        order_list = order_str.split(",");
                        payload_list = textArea_payload.getText().split("\n");
                    }
                });

                splitPanes_left.setLeftComponent(jp_l_up);//上面
                splitPanes_left.setRightComponent(jp_l_down);//下面
                splitPanes_rigth.setLeftComponent(jp_r_up);//上面
                splitPanes_rigth.setRightComponent(jp_payload);//下面
                splitPane.setLeftComponent(splitPanes_left);//左边
                splitPane.setRightComponent(splitPanes_rigth);//右边
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(logTable_l);
                callbacks.customizeUiComponent(logTable_r);
                callbacks.customizeUiComponent(jp_r_up);
                callbacks.customizeUiComponent(jp_l_up);
                callbacks.customizeUiComponent(jp_l_down);
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScannerCheck(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);
            }
        });

    }
    @Override
    public String getTabCaption() {
        return "XG_SQL";
    }
    @Override
    public Component getUiComponent() {
        return splitPane;
    }
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (switchs == 1) {//插件开关
            if (toolFlag == clicks_Repeater || toolFlag == clicks_Proxy) {//监听Repeater
                if (!messageIsRequest) {
                    synchronized (log_raw) {
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(messageInfo, toolFlag);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }
                }
            }
        }
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(2);
        if (invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER || invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_PROXY) {
            IHttpRequestResponse[] responses = invocation.getSelectedMessages();

            JMenuItem jMenu = new JMenuItem("Send to XG_SQL");
            jMenu.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (switchs == 1) {
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(responses[0], 1024);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    } else {
                        BurpExtender.this.stdout.println("插件XG_SQL关闭状态！");
                    }
                }
            });

            JMenuItem jMenu_json = new JMenuItem("Send to JsonParam");
            jMenu_json.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (switchs == 1) {
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkJson(responses[0], 1024);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    } else {
                        BurpExtender.this.stdout.println("插件XG_SQL关闭状态！");
                    }
                }
            });
            listMenuItems.add(jMenu);
            listMenuItems.add(jMenu_json);
        }
        return listMenuItems;
    }

    private void checkVul(IHttpRequestResponse baseRequestResponse, int toolFlag ) throws Exception {

        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        int raw_length = baseRequestResponse.getResponse().length;

        int is_add; //用于判断是否要添加扫描
        String change_sign_1 = "";

        //把当前url和参数进行md5加密，用于判断该url是否已经扫描过
        List<IParameter> paraLists = requestInfo.getParameters();
        temp_data = String.valueOf(requestInfo.getUrl());//url
        String[] temp_data_strarray = temp_data.split("\\?");
        String temp_data = temp_data_strarray[0];//获取问号前面的字符串

        //检测白名单
        String[] white_URL_list = white_URL.split(",");
        int white_swith = 0;
        if (white_switchs == 1) {
            white_swith = 0;
            for (int i = 0; i < white_URL_list.length; i++) {
                if (temp_data.contains(white_URL_list[i])) {
                    stdout.println("白名单URL！" + temp_data);
                    white_swith = 1;
                }
            }
            if (white_swith == 0) {
                stdout.println("不是白名单URL！" + temp_data);
                return;
            }
        }

        //用于判断页面后缀是否为静态文件
        if (toolFlag == 4 || toolFlag == 64) {
            String[] static_file_1 = temp_data.split("\\.");
            String static_file_Extension = static_file_1[static_file_1.length - 1].toLowerCase();//后缀
            for (String i : static_file_list) {
                if (static_file_Extension.equals(i)) {
                    if(is_debug == true){stdout.println("当前url为静态文件:" + temp_data + "\n");}
                    return;
                }
            }

            IResponseInfo responseInfo = this.callbacks.getHelpers().analyzeResponse(baseRequestResponse.getResponse());
            byte[] responseBody = Arrays.copyOfRange(baseRequestResponse.getResponse(), responseInfo.getBodyOffset(), baseRequestResponse.getResponse().length);
            InputStream inputStream = new ByteArrayInputStream(responseBody);
            int i = 0;
            byte[] buffer = new byte[8];

            try {
                i = inputStream.read(buffer);
            } catch (IOException var38) {
                var38.printStackTrace();
            }

            if (i >= 2 && buffer[0] == -1 && buffer[1] == -40) {
                if(is_debug == true){stdout.println("当前url的响应包为jpg图片：" + temp_data + "\n");}
                return;
            }else if(i >= 4 && buffer[0] == -119 && buffer[1] == 80 && buffer[2] == 78 && buffer[3] == 71) {
                if(is_debug == true){stdout.println("当前url的响应包为png图片：" + temp_data + "\n");}
                return;
            }else if(i >= 2 && buffer[0] == 71 && buffer[1] == 73) {
                if(is_debug == true){stdout.println("当前url的响应包为gif图片：" + temp_data + "\n");}
                return;
            }
        }

        is_add = 0;

        for (IParameter para : paraLists) {// 循环获取参数，判断类型，再构造新的参数，合并到新的请求包中。
            if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6 || para.getType() == is_cookie) {
                if (is_add == 0) {
                    is_add = 1;
                }
                temp_data += "+" + para.getName();
            }
        }
        temp_data += "+" + helpers.analyzeRequest(baseRequestResponse).getMethod();
        String temp_data_md5 = MD5(temp_data);
        if(is_debug == true){
            stdout.println("\nMD5(\"" + temp_data + "\")");
            stdout.println(temp_data_md5);
        }
        for (Request_md5 i : log_md5) {
            if (i.md5_data.equals(temp_data_md5)) {//判断md5值是否一样，且右键发送过来的请求不进行md5验证
                if (toolFlag == 1024) {
                    temp_data = String.valueOf(System.currentTimeMillis());
                } else {
                    return;
                }
            }
        }

        //用于判断是否要处理这个请求
        if (is_add != 0) {
            log_md5.add(new Request_md5(temp_data_md5));//保存对应对md5
            int row = log_raw.size();
            try {
                original_data_len = callbacks.saveBuffersToTempFiles(baseRequestResponse).getResponse().length;//更新原始数据包的长度
                if (original_data_len <= 0) {
                    stdout.println("该数据包无响应");
                    return;
                }
            } catch (Exception ex) {
                stdout.println("该数据包无响应");
                return;
            }
            log_raw.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(baseRequestResponse), helpers.analyzeRequest(baseRequestResponse).getUrl(), "", "", "", temp_data, 0, "run……", 999));
            conut += 1;
            fireTableRowsInserted(row, row);
        }

        //处理参数
        List<IParameter> paraList = helpers.analyzeRequest(baseRequestResponse).getParameters();
        byte[] request_raw = baseRequestResponse.getRequest();

        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String contentType = null;
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type:")) {
                contentType = header.split(":")[1].trim(); // 获取 Content-Type 的值
                break;
            }
        }



        for (IParameter para : paraList) {// 循环获取参数
            if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6 || para.getType() == is_cookie) { //getTpe()就是来判断参数是在那个位置的
                String key = para.getName();//获取参数的名称
                String value_raw = para.getValue();//获取参数的值

                //排除参数
                List<String> noscan_page_list = Arrays.asList(page_list);
                if(is_noscan_page == true && noscan_page_list.contains(key.toLowerCase())){
                    if( is_debug == true ){stdout.println("参数："+key+"跳过");}
                    continue;
                }

                byte[] bytes = value_raw.getBytes(StandardCharsets.ISO_8859_1);
                String value = new String(bytes, StandardCharsets.UTF_8);
                if(is_debug==true){stdout.println("原始数据：" + key + ":" + value + "\n");}

                //payload
                ArrayList<String> payloads = new ArrayList<>();
                payloads.add("'''");
                payloads.add("''''");
                if (value.matches("[0-9]+")) {
                    payloads.add("/xxgg");
                    payloads.add("/1");
                }
                if (key.matches("(.*)sort(.*)") || key.matches("(.*)order(.*)") || key.matches("(.*)(?i)ASC(.*)") || key.matches("(.*)(?i)DESC(.*)")) {
                    payloads.add("/*xxgg/");
                    payloads.add("/*xxgg*/");
                }
                if (value.matches("(.*)ASC(.*)") || value.matches("(.*)DESC(.*)")) {
                    payloads.add("/*xxgg/");
                    payloads.add("/*xxgg*/");
                }
                if (key.matches("(.*)table(.*)") || key.matches("(.*)column(.*)")) {
                    payloads.add("/*xxgg/");
                    payloads.add("/*xxgg*/");
                }
                if (is_mybatis == true) {//mybaties型开关
                    payloads.add("#{xxgg}");
                    payloads.add("#xxgg}");
                }
                if (is_Zpayload == true) {//自定义payload
                    for (String a : payload_list) {
                        if (!a.isEmpty()){
                            payloads.add(a);
                        }
                    }
                }

                int change_1 = 0; //用于判断返回包长度是否一致、保存第一次请求响应的长度
                int change_2 = 0;
                for (String payload : payloads) {
                    if( is_sleep == true ){Thread.sleep(sleep_time);}//放缓请求速度

                    IHttpRequestResponse requestResponse = null;
                    int time_1 = 0, time_2 = 0;

                    if(para.getType() == 6){
                        int valueStart = para.getValueStart();
                        int valueEnd = para.getValueEnd();
                        String payload_json;

                        if(para.getValue().contains("true")||para.getValue().contains("false")||para.getValue().contains("null")){
                            payload_json = "\""+escapeJsonString(payload)+"\"";
                        }else{
                            if(request_raw[valueStart-1]==34){
                                payload_json = para.getValue()+escapeJsonString(payload);
                            }else {
                                payload_json = "\""+escapeJsonString(para.getValue()+payload)+"\"";
                            }
                        }
                        byte[] new_Requests_raw = new byte[request_raw.length-para.getValue().length()+payload_json.length()];
                        byte[] newValueBytes = payload_json.getBytes(StandardCharsets.ISO_8859_1);
                        System.arraycopy(request_raw, 0, new_Requests_raw, 0, valueStart);
                        System.arraycopy(newValueBytes, 0, new_Requests_raw, valueStart, newValueBytes.length);
                        System.arraycopy(request_raw, valueEnd, new_Requests_raw, valueStart + newValueBytes.length, request_raw.length - valueEnd);

                        String request_data = helpers.bytesToString(new_Requests_raw).split("\r\n\r\n")[1];
                        byte[] new_Requests_body = helpers.buildHttpMessage(headers, request_data.getBytes(StandardCharsets.ISO_8859_1));
                        time_1 = (int) System.currentTimeMillis();
                        requestResponse = callbacks.makeHttpRequest(iHttpService,new_Requests_body);
                        time_2 = (int) System.currentTimeMillis();

                        if(is_debug == true){
                            stdout.println("json数据:");
                            stdout.println(new String(request_data.getBytes(StandardCharsets.ISO_8859_1)));
                            stdout.println("##########################################\n");
                        }
                    }else if(para.getType() == 0 || para.getType() == 2){
                        IParameter newPara = helpers.buildParameter(para.getName(),para.getValue() + URLencode(payload), para.getType()); //构造新的参数
                        byte[] newRequest = helpers.updateParameter(request_raw, newPara);
                        time_1 = (int) System.currentTimeMillis();
                        requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);
                        time_2 = (int) System.currentTimeMillis();
                        if(is_debug==true){
                            stdout.println("普通参数:");
                            stdout.println(new String(newRequest));
                            stdout.println("##########################################\n");
                        }
                    }else if(para.getType() == 1){
                        if (!contentType.contains("application/x-www-form-urlencoded") && !contentType.contains("multipart/form-data")) {
                            if(is_debug==true){
                                stdout.println("当前BODY数据为二进制:");
                                stdout.println(new String(request_raw));
                                stdout.println("##########################################\n");}
                            return;
                        }
                        IParameter newPara = helpers.buildParameter(para.getName(),para.getValue() + URLencode(payload), para.getType()); //构造新的参数
                        byte[] newRequest = helpers.updateParameter(request_raw, newPara);
                        time_1 = (int) System.currentTimeMillis();
                        requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);
                        time_2 = (int) System.currentTimeMillis();

                        if(is_debug==true){
                            stdout.println("BODY数据:");
                            stdout.println(new String(newRequest));
                            stdout.println("##########################################\n");
                        }
                    }



                    //判断数据长度是否会变化
                    String change_sign;//第二个表格中 变化 的内容
                    if (payload == "'''" || payload == "#{xxgg}" || payload == "/xxgg" || payload == "/*xxgg/" || change_1 == 0) {
                        change_1 = requestResponse.getResponse().length;
                        change_sign = "";
                    } else {
                        if (payload == "''''" || payload == "#xxgg}" || payload == "/1" || payload == "/*xxgg*/") {
                            change_2 = requestResponse.getResponse().length;
                            if (change_1 != change_2) {
                                change_sign = "✔ " + (change_1 - change_2);
                                change_sign_1 = "✔ ";
                            } else {
                                change_sign = "";
                            }
                        } else {
                            if (time_2 - time_1 >= 3000) {
                                change_sign = "time > 3";
                                change_sign_1 = "✔";
                            } else {
                                change_sign = "diy payload";
                            }
                        }
                    }
                    //把响应内容保存在log2中
                    log2.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(requestResponse), helpers.analyzeRequest(requestResponse).getUrl(), key, value + payload, change_sign, temp_data, time_2 - time_1, "end", helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                }
            }
        }

        //add_order扫描
        if ( is_add_order == true ){
            String order_value = "xxgg_aabb";
            String change_sign;
            if (requestInfo.getMethod().contains("GET")){
                for (String order_par : order_list){
                    if( is_sleep == true ){Thread.sleep(sleep_time);}//放缓请求速度

                    String order_par2 = URLencode(order_par);
                    IParameter newPara = helpers.buildParameter(order_par2,order_value,(byte)0);
                    byte[] newRequest = helpers.addParameter(request_raw, newPara);
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);

                    int add_order_length = requestResponse.getResponse().length;
                    if (raw_length != add_order_length){
                        change_sign = "!! "+(raw_length-add_order_length);
                    }else {
                        change_sign = "";
                    }
                    log2.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(requestResponse), helpers.analyzeRequest(requestResponse).getUrl(), order_par, order_value, change_sign, temp_data, 0, "end", helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                }
            }else if(requestInfo.getMethod().contains("POST")){
                if (contentType.contains("application/x-www-form-urlencoded") || contentType.contains("multipart/form-data")) {
                    for (String order_par : order_list){
                        if( is_sleep == true ){Thread.sleep(sleep_time);}//放缓请求速度

                        IParameter newPara = helpers.buildParameter(order_par,order_value,(byte)1);
                        byte[] newRequest = helpers.addParameter(request_raw, newPara);
                        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);

                        int add_order_length = requestResponse.getResponse().length;
                        if (raw_length != add_order_length){
                            change_sign = "!! "+(raw_length-add_order_length);
                        }else {
                            change_sign = "";
                        }
                        log2.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(requestResponse), helpers.analyzeRequest(requestResponse).getUrl(), order_par, order_value, change_sign, temp_data, 0, "end", helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                    }
                }else if(contentType.contains("application/json")){
                    for (String order_par : order_list){
                        if( is_sleep == true ){Thread.sleep(sleep_time);}//放缓请求速度

                        String s = new String(request_raw,StandardCharsets.ISO_8859_1);
                        List<Integer> positions = findAllBracePositionsInJson(s);
                        for (int ii: positions){
                            int valueStart = ii;

                            String payload_json = ",\""+order_par+"\":\""+order_value+"\"";
                            byte[] new_Requests_raw = new byte[request_raw.length+payload_json.length()];
                            byte[] newValueBytes = payload_json.getBytes(StandardCharsets.ISO_8859_1);
                            System.arraycopy(request_raw, 0, new_Requests_raw, 0, valueStart);
                            System.arraycopy(newValueBytes, 0, new_Requests_raw, valueStart, newValueBytes.length);
                            System.arraycopy(request_raw, valueStart, new_Requests_raw, valueStart + newValueBytes.length, request_raw.length-valueStart);
                            String request_data = helpers.bytesToString(new_Requests_raw).split("\r\n\r\n")[1];
                            byte[] new_Requests_body = helpers.buildHttpMessage(headers, request_data.getBytes(StandardCharsets.ISO_8859_1));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(iHttpService,new_Requests_body);

                            int add_order_length = requestResponse.getResponse().length;
                            if (raw_length != add_order_length){
                                change_sign = "!! "+(raw_length-add_order_length);
                            }else {
                                change_sign = "";
                            }
                            log2.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(requestResponse), helpers.analyzeRequest(requestResponse).getUrl(), order_par, order_value, change_sign, temp_data, 0, "end", helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                        }
                    }
                }else {
                    stdout.println("仅支持GET、POST");
                }
            }
        }

        //用于更新是否已经跑完所有payload的状态
        for (int i = 0; i < log_raw.size(); i++) {
            if (temp_data.equals(log_raw.get(i).data_md5)) {
                log_raw.get(i).setState("end!" + change_sign_1);
            }
        }

        BurpExtender.this.fireTableDataChanged();
        BurpExtender.this.logTable.setRowSelectionInterval(BurpExtender.this.select_row, BurpExtender.this.select_row);
    }

    //json数据检测
    private void checkJson(IHttpRequestResponse baseRequestResponse, int toolFlag ) throws Exception {

        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        byte[] request_raw = baseRequestResponse.getRequest();
        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<IParameter> paraList = helpers.analyzeRequest(baseRequestResponse).getParameters();

        String change_sign_1 = "";
        String change_sign_2 = "";
        int row = log_raw.size();
        try {
            original_data_len = callbacks.saveBuffersToTempFiles(baseRequestResponse).getResponse().length;//更新原始数据包的长度
            if (original_data_len <= 0) {
                stdout.println("该数据包无响应");
                return;
            }
        } catch (Exception ex) {
            stdout.println("该数据包无响应");
            return;
        }

        String flag_md5 = MD5(String.valueOf(requestInfo.getUrl())+String.valueOf(System.currentTimeMillis()));//URL+时间戳的md5
        log_raw.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(baseRequestResponse), helpers.analyzeRequest(baseRequestResponse).getUrl(), "", "", "", flag_md5, 0, "run……", 999));
        conut += 1;
        fireTableRowsInserted(row, row);


        for (IParameter para : paraList) {// 循环获取参数
            if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6) { //判断参数是在那个位置的
                String key = para.getName();//获取参数的名称
                String value_raw = para.getValue();//获取参数的值

                String encode;
                if(value_raw.startsWith("{\"")||value_raw.startsWith("[{\"")){
                    encode = "NO";
                }else if (value_raw.startsWith("%7b")||value_raw.startsWith("%5b%7b")){
                    value_raw = decodeUrl(value_raw, StandardCharsets.ISO_8859_1);
                    encode = "URL";
                }else if(value_raw.startsWith("{\\\"")||value_raw.startsWith("[{\\\"")){
                    value_raw = value_raw.replace("\\\"","\"");
                    encode = "JSON";
                }else {
                    continue;
                }

                String GG_string = "POST /testjson HTTP/1.1\r\n" +
                        "Host: 127.0.0.1:8888\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Content-Length:"+value_raw.length()+"\r\n"+
                        "\r\n"+value_raw;
                byte[] GG_raw = GG_string.getBytes(StandardCharsets.ISO_8859_1);
                List<IParameter> GG_parameters = helpers.analyzeRequest(GG_raw).getParameters();
                for (IParameter GG_para : GG_parameters) {
                    String GG_key = GG_para.getName();
                    String GG_value_raw = GG_para.getValue();

                    byte[] bytes = GG_value_raw.getBytes(StandardCharsets.ISO_8859_1);
                    String value = new String(bytes, StandardCharsets.UTF_8);

                    //排除参数
                    List<String> noscan_page_list = Arrays.asList(page_list);
                    if(is_noscan_page == true && noscan_page_list.contains(GG_key.toLowerCase())){
                        if( is_debug == true ){stdout.println("参数："+GG_key+"跳过");}
                        continue;
                    }

                    //payload
                    ArrayList<String> payloads = new ArrayList<>();
                    payloads.add("'''");
                    payloads.add("''''");
                    if (GG_value_raw.matches("[0-9]+")) {
                        payloads.add("/xxgg");
                        payloads.add("/1");
                    }
                    if (GG_key.matches("(.*)sort(.*)") || GG_key.matches("(.*)order(.*)") || GG_key.matches("(.*)(?i)ASC(.*)") || GG_key.matches("(.*)(?i)DESC(.*)")) {
                        payloads.add("/*xxgg/");
                        payloads.add("/*xxgg*/");
                    }
                    if (GG_value_raw.matches("(.*)ASC(.*)") || GG_value_raw.matches("(.*)DESC(.*)")) {
                        payloads.add("/*xxgg/");
                        payloads.add("/*xxgg*/");
                    }
                    if (GG_key.matches("(.*)table(.*)") || GG_key.matches("(.*)column(.*)")) {
                        payloads.add("/*xxgg/");
                        payloads.add("/*xxgg*/");
                    }
                    if (is_mybatis == true) {//mybaties型开关
                        payloads.add("#{xxgg}");
                        payloads.add("#xxgg}");
                    }
                    if (is_Zpayload == true) {//自定义payload
                        for (String a : payload_list) {
                            if (!a.isEmpty()){
                                payloads.add(a);
                            }
                        }
                    }

                    int change_length_1 = 0;
                    int change_length_2 = 0;
                    for (String payload : payloads) {
                        int GG_valueStart = GG_para.getValueStart();
                        int GG_valueEnd = GG_para.getValueEnd();
                        String GG_payload_json;
                        if(GG_value_raw.contains("true")||GG_value_raw.contains("false")||GG_value_raw.contains("null")){
                            GG_payload_json = "\""+escapeJsonString(payload)+"\"";
                        }else{
                            if(GG_raw[GG_valueStart-1]==34){
                                GG_payload_json = GG_value_raw+escapeJsonString(payload);
                            }else {
                                GG_payload_json = "\""+escapeJsonString(GG_value_raw+payload)+"\"";
                            }
                        }
                        byte[] GG_new_Requests_raw = new byte[GG_raw.length-GG_value_raw.length()+GG_payload_json.length()];
                        byte[] GG_newValueBytes = GG_payload_json.getBytes(StandardCharsets.ISO_8859_1);
                        System.arraycopy(GG_raw, 0, GG_new_Requests_raw, 0, GG_valueStart);
                        System.arraycopy(GG_newValueBytes, 0, GG_new_Requests_raw, GG_valueStart, GG_newValueBytes.length);
                        System.arraycopy(GG_raw, GG_valueEnd, GG_new_Requests_raw, GG_valueStart + GG_newValueBytes.length, GG_raw.length - GG_valueEnd);
                        String GG_json_data = helpers.bytesToString(GG_new_Requests_raw).split("\r\n\r\n")[1];

                        switch (encode) {
                            case "URL":
                                GG_json_data = URLencode(GG_json_data);
                                break;
                            case "JSON":
                                GG_json_data = GG_json_data.replace("\"","\\\"");
                                break;
                            default:
                        }

                        if( is_sleep == true ){Thread.sleep(sleep_time);}//放缓请求速度
                        IHttpRequestResponse requestResponse = null;
                        int time_1 = 0, time_2 = 0;
                        int valueStart = para.getValueStart();
                        int valueEnd = para.getValueEnd();
                        String payload_json = GG_json_data;
                        byte[] new_Requests_raw = new byte[request_raw.length-value_raw.length()+payload_json.length()];
                        byte[] newValueBytes = payload_json.getBytes(StandardCharsets.ISO_8859_1);
                        System.arraycopy(request_raw, 0, new_Requests_raw, 0, valueStart);
                        System.arraycopy(newValueBytes, 0, new_Requests_raw, valueStart, newValueBytes.length);
                        System.arraycopy(request_raw, valueEnd, new_Requests_raw, valueStart + newValueBytes.length, request_raw.length - valueEnd);
                        if (para.getType() == 0){
                            time_1 = (int) System.currentTimeMillis();
                            requestResponse = callbacks.makeHttpRequest(iHttpService,new_Requests_raw);
                            time_2 = (int) System.currentTimeMillis();
                        }else if (para.getType() == 1 || para.getType() == 6){
                            String request_data = helpers.bytesToString(new_Requests_raw).split("\r\n\r\n",2)[1];
                            byte[] new_Requests_body = helpers.buildHttpMessage(headers, request_data.getBytes(StandardCharsets.ISO_8859_1));
                            time_1 = (int) System.currentTimeMillis();
                            requestResponse = callbacks.makeHttpRequest(iHttpService,new_Requests_body);
                            time_2 = (int) System.currentTimeMillis();
                        }

                        //判断数据长度是否会变化
                        if (payload == "'''" || payload == "#{xxgg}" || payload == "/xxgg" || payload == "/*xxgg/" || change_length_1 == 0) {
                            change_length_1 = requestResponse.getResponse().length;
                            change_sign_2 = "";
                        } else {
                            if (payload == "''''" || payload == "#xxgg}" || payload == "/1" || payload == "/*xxgg*/") {
                                change_length_2 = requestResponse.getResponse().length;
                                if (change_length_1 != change_length_2) {
                                    change_sign_2 = "✔ " + (change_length_1 - change_length_2);
                                    change_sign_1 = "✔ ";
                                } else{
                                    change_sign_2 = "";
                                }
                            }
                            else {
                                if (time_2 - time_1 >= 3000) {
                                    change_sign_2 = "time > 3";
                                    change_sign_1 = "✔";
                                } else {
                                    change_sign_2 = "diy payload";
                                }
                            }
                        }
                        //把响应内容保存在log2中
                        log2.add(new LogEntry(conut, toolFlag, callbacks.saveBuffersToTempFiles(requestResponse), helpers.analyzeRequest(requestResponse).getUrl(), GG_key, value + payload, change_sign_2, flag_md5, time_2 - time_1, "end", helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                    }
                }
            }
        }

        //用于更新是否已经跑完所有payload的状态
        if (flag_md5.equals(log_raw.get(row).data_md5)){
            log_raw.get(row).setState("end!" + change_sign_1);
        }else {
            for (int i = 0; i < log_raw.size(); i++) {
                if (flag_md5.equals(log_raw.get(i).data_md5)) {
                    log_raw.get(i).setState("end!" + change_sign_1);
                }
            }
        }

        BurpExtender.this.fireTableDataChanged();
        BurpExtender.this.logTable.setRowSelectionInterval(BurpExtender.this.select_row, BurpExtender.this.select_row);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) return -1;
        else return 0;
    }

    @Override
    public int getRowCount() {
        return log_raw.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "来源";
            case 2:
                return "URL";
            case 3:
                return "返回包长度";
            case 4:
                return "状态";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log_raw.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.id;
            case 1:
                return callbacks.getToolName(logEntry.tool);
            case 2:
                return logEntry.url.toString();
            case 3:
                return logEntry.requestResponse.getResponse().length;
            case 4:
                return logEntry.state;
            default:
                return "";
        }
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }


    //存放数据包的md5值，用于匹配该数据包已请求过
    private static class Request_md5 {
        final String md5_data;
        Request_md5(String md5_data) {
            this.md5_data = md5_data;
        }
    }

    private static class LogEntry {
        final int id;
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;
        final String parameter;
        final String value;
        final String change;
        final String data_md5;
        final int times;
        final int response_code;
        String state;


        LogEntry(int id, int tool, IHttpRequestResponsePersisted requestResponse, URL url, String parameter, String value, String change, String data_md5, int times, String state, int response_code) {
            this.id = id;
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.parameter = parameter;
            this.value = value;
            this.change = change;
            this.data_md5 = data_md5;
            this.times = times;
            this.state = state;
            this.response_code = response_code;
        }

        public String setState(String state) {
            this.state = state;
            return this.state;
        }
    }

    //log_show页面
    class log_show_Model extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return log_show.size();
        }

        @Override
        public int getColumnCount() {
            return 6;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return "参数";
                case 1:
                    return "payload";
                case 2:
                    return "返回包长度";
                case 3:
                    return "变化";
                case 4:
                    return "用时";
                case 5:
                    return "响应码";
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            LogEntry logEntry2 = log_show.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    return logEntry2.parameter;
                case 1:
                    return logEntry2.value;
                case 2:
                    return logEntry2.requestResponse.getResponse().length;
                case 3:
                    return logEntry2.change;
                case 4:
                    return logEntry2.times;
                case 5:
                    return logEntry2.response_code;
                default:
                    return "";
            }
        }
    }

    private class Table extends JTable {
        public Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            LogEntry logEntry = log_raw.get(row);
            data_md5_id = logEntry.data_md5;
            select_row = logEntry.id;

            log_show.clear();
            for (int i = 0; i < log2.size(); i++) {//筛选出目前选中的原始数据包--》衍生出的带有payload的数据包
                if (log2.get(i).data_md5 == data_md5_id) {
                    log_show.add(log2.get(i));
                }
            }
            //刷新列表界面
            model.fireTableRowsInserted(log_show.size(), log_show.size());
            model.fireTableDataChanged();

            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class Table_log2 extends JTable {
        public Table_log2(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {

            // show the log entry for the selected row
            LogEntry logEntry = log_show.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    public static String MD5(String key) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        try {
            byte[] btInput = key.getBytes();
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            mdInst.update(btInput);
            byte[] md = mdInst.digest();
            int j = md.length;
            char[] str = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }

    public static String URLencode(String payload){
        Map<String, String> maps = new HashMap<String,String>();
        maps.put("\"","%22");
        maps.put("#","%23");
        maps.put("{","%7b");
        maps.put("}","%7d");
        maps.put(" ","%20");
        maps.put("+","%2b");
        maps.put("/","%2f");
        maps.put("[","%5b");
        maps.put("]","%5d");
        maps.put("<","%3c");
        maps.put("=","%3d");
        maps.put(">","%3e");
        maps.put("&","%26");
        maps.put("\\","%5c");
        Set<String> keys = maps.keySet();
        for(String key:keys){
            payload = payload.replace(key, maps.get(key));
        }
        return payload;
    }

    public static String decodeUrl(String str, Charset charset) {
        try {
            return URLDecoder.decode(str, charset.toString());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("不支持的编码: " + charset, e);
        }
    }

    public static List<Integer> findAllBracePositionsInJson(String jsonStr) {
        List<Integer> positions = new ArrayList<>();
        boolean inString = false;
        boolean escapeNext = false;

        for (int i = 0; i < jsonStr.length(); i++) {
            char c = jsonStr.charAt(i);
            if (escapeNext) {
                escapeNext = false;
                continue;
            }
            if (c == '\\') {
                escapeNext = true;
            } else if (c == '"') {
                inString = !inString;
            } else if (c == '}' && !inString) {
                positions.add(i);
            }
        }
        return positions;
    }

    public static String escapeJsonString(String str) {
        if (str == null) return null;
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

}
