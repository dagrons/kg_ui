const MALWARE_ID = new URLSearchParams(window.location.search).get("name");
// G6s设置

const COLOR_SET = [
  "#dd6b66",
  "#759aa0",
  "#e69d87",
  "#8dc1a9",
  "#ea7e53",
  "#eedd78",
  "#73a373",
  "#73b9bc",
  "#7289ab",
  "#91ca8c",
  "#f49f42",
];


const graph = createGraph();
graph.query(MALWARE_ID);


//添加侧边栏动作
//侧边栏图标
window.onload = async function() {
  const statistics = await getData('MATCH (n) RETURN distinct labels(n), count(n)');
  var stat_data = [];
  for (var i in statistics) {
    var name = statistics[i]._fields[0][0]
    var value = statistics[i]._fields[1].low
    if (name != '外部引用')
      stat_data.push({
        name,
        value
      });
  }
  var chart_option = {
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b} : {c} ({d}%)'
    },
    theme: 'dark',
    series: [{
      name: '实体类型',
      type: 'pie',
      radius: '55%',
      center: ['50%', '60%'],
      data: stat_data,
      emphasis: {
        itemStyle: {
          shadowBlur: 10,
          shadowOffsetX: 0,
          shadowColor: 'rgba(0, 0, 0, 0.5)'
        }
      }
    }]
  };

  var myChart = echarts.init(document.getElementById('chartmain'), 'dark');

  //使用制定的配置项和数据显示图表
  myChart.setOption(chart_option);

};

async function getFromNeo4j(para) {
  return await axios.get(`/api/kg/all?query=${para}`)
}

async function getData(para) {
  let neo4jData = await getFromNeo4j(para);
  return neo4jData.data.records
}
//展示图谱字段

$(function() {
  const entity_list = ['IP', 'Mail', 'URL', 'Malware', 'DLL']; //neo4j中的实体
  for (let entity in entity_list) {
    $('#entity').append('<button class=' + "entity_btn" + ' onclick="graph.query(this,mode=4)">' + entity_list[entity] + '</button>')
  }

  const rela_list = ['Mail', 'IP', 'URL', 'Malware', 'DLL'];
  for (let relation in rela_list) {
    $('#relation').append('<button class=' + "rela_btn" + ' onclick="graph.query(this,mode=5)" >' + rela_list[relation] + '</button>') //neo4j中的关系
  }
});



//结束侧边栏动作



// 为按钮绑定动作
const currentButton = document.querySelector('#current-button');
const ipButton = document.querySelector('#ip-button');
const mailButton = document.querySelector('#mail-button');
const urlButton = document.querySelector('#url-button');


currentButton.addEventListener('click', e=> {
  graph.query(MALWARE_ID);
})
ipButton.addEventListener('click', e => {
  graph.query("", mode=1);
});
mailButton.addEventListener('click', e=> {
  graph.query('', mode=2);
})
urlButton.addEventListener('click', e=>{
  graph.query('', mode=3);
})


function createG6Ins() {
  // create a g6 instance
  G6.registerBehavior('node-activate', {
    getDefaultCfg() {
      return {
        multiple: true
      };
    },
    getEvents() {
      return {
        'node:mouseenter': 'onMouseenter'
      };
    },
    onMouseenter(e) {
      $('#proul').children().remove();
      $('#proul').append(
          '<ul class="pro_slider"><li><b>' + 'type' + ' : </b> ' +  e.item.getModel().type + '</li><br>')
      $('#proul').append(
          '<ul class="pro_slider"><li><b>' + 'Label' + ' : </b> ' +  e.item.getModel().label + '</li><br>')
      $('#proul').append(
          '<ul class="pro_slider"><li><b>' + 'ID' + ' : </b> ' +  e.item.getModel().id + '</li>')
    },
  });

  const graph = new G6.Graph({
    container: "mountNode",
    width: window.screen.availWidth,
    height: document.body.clientHeight,

    modes: {
      default: ["drag-node", "node-activate"],
    },

    layout: {
      type: "force",
      center: [
        window.screen.availWidth * 0.45,
        document.body.clientHeight * 0.4,
      ],
      preventOverlap: true,
      linkDistance: 180,
    },

    defaultNode: {
      size: 28,
      color: "#5B8FF9",
      style: {
        lineWidth: 2,
        fill: "",
        stroke: "",
      },
      label: "node-label",
      labelCfg: {
        position: "top",
        style: {
          fill: "#434343",
        },
      },
    },
    defaultEdge: {
      size: 1,
      color: "#aaa",
      label: "node-label",
      labelCfg: {
        style: {
          fill: "#434343",
          stroke: "",
        },
      },
    },
  });

  function updateNodePostion(e) {
    const model = e.item.get("model");
    model.fx = e.x;
    model.fy = e.y;
  }

  graph.on("node:dragstart", (e) => {
    graph.layout();
    updateNodePostion(e);
  });
  graph.on("node:drag", (e) => {
    updateNodePostion(e);
  });

  return graph;
}

function createGraph() {
  // graph: g6(I) + query(M)
  // anonymous function: create the graph instance
  // factory pattern
  // 工厂模式，为g6ins绑定了query方法再返回
  // query方法用于neo4j询问
  const g6ins = createG6Ins();
  g6ins.query = async (param, mode=0) => {
    // fetch data and render graph
    let q = "";
    if (mode == 0) {
      q =
          'MATCH p=(n{name:"' +
          param +
          '"})-[r:URL|Mail|IP]-(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 100';
    } else if (mode == 1) {
      q = 'MATCH p=(n)-[r:IP]->(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 50';
    } else if (mode == 2) {
      q = 'MATCH p=(n)-[r:Mail]->(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 50';
    } else if (mode == 3){
      q = 'MATCH p=(n)-[r:URL]->(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 50';
    }else if (mode == 4) {
      q = 'MATCH p=(n:"' +
          param +
          '")-[a]-(x) RETURN n,labels(n),a,type(a),x,labels(x) LIMIT 100';
    } else if (mode == 5) {
      q = 'match (na:Malware)-[ra:"' +
          param +
          '"]->(nd:"' +
          param +
          '")<-[rb:"' +
          param +
          '"]-(nb:Malware) return na,labels(na),ra,type(ra),nd,labels(nd),rb,type(rb),nb,labels(nb) LIMIT 50';
    }
    const res = await axios.get(`/api/kg/?query=${q}`);
    const data = transform(res);
    setStyle(data);
    g6ins.data(data);
    g6ins.render();
    // register node:click behavior on g
    g6ins.on("node:click", (e) => {
      g6ins.query(e.item.getModel().label);
    });

    function setStyle(data) {
      // set node style
      // 根据node的类型决定大小
      // data is G6 data = {nodes, edges}
      const nodes = data.nodes;
      nodes.forEach((node) => {
        node.style = {
          fill: COLOR_SET[node.id % COLOR_SET.length], // random color...
          stroke: "",
        };
        switch (node.type) {
          case "IP" || "Mail": {
            node.size = 36;
            break;
          }
          case "DLL" || "URL": {
            node.size = 36;
            break;
          }
        }
      });
    }

    function transform(res) {
      // transform from res to G6 data
      // 格式转换, 从neo4j的返回数据格式映射到G6需要的数据格式
      nodes = [];
      edges = [];

      const records = res.data.records;

      if (records.length === 0) {
        alert("该恶意样本无关联特征");
      }

      // 找到所有节点
      let st = {};
      let cnt = 0;
      let mp = {};
      for (let i = 0; i < records.length; i++) {
        let record = records[i];
        if (st[record._fields[0].properties.name]) continue;
        st[record._fields[0].properties.name] = true;
        nodes.push({
          id: cnt.toString(),
          label: record._fields[0].properties.name,
          type: records[i]._fields[1][0],
        })
        mp[record._fields[0].properties.name] = cnt;
        cnt++;
      }
      for (let i = 0; i < records.length; i++) {
        let record = records[i];
        if (st[record._fields[4].properties.name]) continue;
        st[record._fields[4].properties.name] = true;
        nodes.push({
          id: cnt.toString(),
          label: record._fields[4].properties.name,
          type: records[i]._fields[5][0],
        })
        mp[record._fields[4].properties.name] = cnt;
        cnt++;
      }

      // 找到所有边
      for (let i = 0; i < records.length; i++) {
        let record = records[i];
        edges.push({
          source: mp[record._fields[0].properties.name].toString(),
          target: mp[record._fields[4].properties.name].toString(),
          label: record._fields[5][0]
        })
      }

      return {
        nodes: nodes,
        edges: edges,
      };
    }
  };

  return g6ins;
}
