const URL = new URLSearchParams(window.location.search).get("url"); // kg backend url
const MALWARE_ID = new URLSearchParams(window.location.search).get("name");

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
          fill: "#ddd",
        },
      },
    },
    defaultEdge: {
      size: 1,
      color: "#aaa",
      label: "node-label",
      labelCfg: {
        style: {
          fill: "#ddd",
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
      q = 'MATCH p=(n)-[r:IP]-(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 50';
    } else if (mode == 2) {
      q = 'MATCH p=(n)-[r:Mail]-(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 50';
    } else {
      q = 'MATCH p=(n)-[r:URL]-(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 50';
    }
    const res = await axios.get(`${URL}?query=${q}`);
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
