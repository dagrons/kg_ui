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
  const g6ins = createG6Ins();
  g6ins.query = async (para) => {
    // fetch data and render graph
    const q =
      'MATCH p=(n{name:"' +
      para +
      '"})-[r:URL|Mail|IP]-(m) RETURN n,labels(n),r,type(r),m,labels(m) LIMIT 100';
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

      const subject = {
        id: "0",
        label: records[0]._fields[0].properties.name,
        type: records[0]._fields[1][0],
      };
      nodes.push(subject);

      for (let i = 0; i < records.length; i++) {
        let j = i + 1;
        edges.push({
          source: "0",
          target: j.toString(),
          label: records[i]._fields[3],
        });
        nodes.push({
          id: j.toString(),
          label: records[i]._fields[4].properties.name,
          type: records[i]._fields[5][0],
        });
      }

      return {
        nodes: nodes,
        edges: edges,
      };
    }
  };

  return g6ins;
}
